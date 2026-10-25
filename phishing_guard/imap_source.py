"""IMAP IDLE acquisition adapter. Intended only for an authorized lab mailbox."""
from __future__ import annotations
import ssl
import time
from imapclient import IMAPClient
from .normalization import normalize_email
from .repository import Repository

class IMAPSource:
    def __init__(self, settings, repository: Repository):
        self.settings, self.repo = settings, repository

    def _connect(self):
        if not self.settings.imap_username or not self.settings.imap_password:
            raise RuntimeError("Configure IMAP_USERNAME e IMAP_PASSWORD en .env")
        ssl_context = ssl.create_default_context()
        if not self.settings.imap_validate_certs:
            # Explicit lab-only opt-out; strongly discouraged.
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        client = IMAPClient(self.settings.imap_host, port=self.settings.imap_port,
                            ssl=self.settings.imap_ssl, ssl_context=ssl_context)
        client.login(self.settings.imap_username, self.settings.imap_password)
        client.select_folder(self.settings.imap_folder)
        return client

    def acquire_unseen(self, client):
        info = client.folder_status(self.settings.imap_folder, ["UIDVALIDITY"])
        uidvalidity = str(info.get(b"UIDVALIDITY", info.get("UIDVALIDITY", "unknown")))
        uids = client.search(["UNSEEN"])
        for uid in uids:
            fetched = client.fetch([uid], [b"RFC822"])
            item = fetched.get(uid, {})
            raw = item.get(b"RFC822")
            if not raw:
                continue
            payload = normalize_email(raw, {
                "account": self.settings.imap_username,
                "folder": self.settings.imap_folder,
                "uidvalidity": uidvalidity,
                "uid": str(uid),
            }, self.settings.max_body_chars)
            mid, inserted = self.repo.store_message(payload, self.settings.imap_username,
                                                    self.settings.imap_folder, uidvalidity, str(uid))
            # Mark Seen only after durable persistence. Do not wait for classification.
            if self.settings.imap_mark_seen_after_persistence:
                client.add_flags([uid], [b"\\Seen"])
            yield mid, inserted

    def listen(self, on_message):
        """Long-running IDLE loop; reconnects and reconciles UNSEEN after disconnects."""
        while True:
            client = None
            try:
                client = self._connect()
                for mid, inserted in self.acquire_unseen(client):
                    if inserted:
                        on_message(mid)
                while True:
                    # IDLE notifications are hints; always reconcile mailbox state after wakeup.
                    with client.idle() as idler:
                        idler.wait(timeout=self.settings.imap_idle_timeout)
                    for mid, inserted in self.acquire_unseen(client):
                        if inserted:
                            on_message(mid)
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(f"[IMAP] conexión/IDLE falló ({type(exc).__name__}); reintentando en 5 s")
                time.sleep(5)
            finally:
                if client is not None:
                    try: client.logout()
                    except Exception: pass
