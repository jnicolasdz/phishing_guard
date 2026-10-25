import argparse
import getpass
from .config import settings
from .repository import Repository
from .classifier import LocalClassifier
from .graph import PhishingWorkflow
from .imap_source import IMAPSource

def build():
    repo = Repository(settings.database_path)
    classifier = LocalClassifier(settings.ollama_base_url, settings.ollama_model, settings.llm_temperature)
    workflow = PhishingWorkflow(repo, classifier, settings)
    return repo, workflow

def main():
    parser = argparse.ArgumentParser(prog="phishing-guard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    sub.add_parser("listen")
    sub.add_parser("process-pending")
    sub.add_parser("review")
    args = parser.parse_args()

    repo = Repository(settings.database_path)
    if args.command == "init-db":
        print(f"SQLite inicializada: {settings.database_path}")
        return

    if args.command == "listen":
        _, workflow = build()
        source = IMAPSource(settings, repo)
        def process(mid):
            print(f"[+] Mensaje {mid} adquirido; ejecutando LangGraph")
            result = workflow.run(mid)
            print(f"    estado={result.get('status')} error={result.get('error', '')}")
        source.listen(process)
        return

    if args.command == "process-pending":
        _, workflow = build()
        statuses = {"RECEIVED", "RETRY_PENDING"}
        pending = [m for status in statuses for m in repo.list_messages(status)]
        for item in pending:
            result = workflow.run(item["id"])
            print(f"message_id={item['id']} status={result.get('status')} error={result.get('error','')}")
        return

    if args.command == "review":
        pending = repo.list_messages("PENDING_REVIEW")
        if not pending:
            print("No hay mensajes pendientes.")
            return
        reviewer = input("Identificador del revisor: ").strip() or getpass.getuser()
        for item in pending:
            mid, payload = item["id"], item["payload"]
            classification = repo.latest_classification(mid) or {}
            print("\n" + "=" * 70)
            print(f"ID: {mid} | Asunto: {payload.get('subject','')}")
            print(f"De: {payload.get('from','')}")
            print(f"Etiqueta: {classification.get('label')} | riesgo: {classification.get('risk_score')}")
            print(f"Evidencias: {classification.get('evidence', [])}")
            print(f"Texto:\n{payload.get('body_text','')[:2000]}")
            print("1=confirmar phishing, 2=confirmar legítimo, 3=mantener pendiente, 4=indeterminado")
            choice = input("Decisión: ").strip()
            mapping = {"1": "phishing", "2": "legitimate", "3": "pending", "4": "undetermined"}
            decision = mapping.get(choice)
            if not decision:
                print("Entrada inválida; no se modifica el caso.")
                continue
            comment = input("Comentario (opcional): ").strip()
            repo.add_review(mid, decision, reviewer, comment)
            if decision == "pending":
                print("Se conserva pendiente.")
            else:
                # Human resolution is recorded; automatic action remains deliberately
                # separate until the IMAP quarantine adapter is configured and tested.
                repo.set_status(mid, "REVIEWED", "review_resolved", {"decision": decision})
                print("Decisión registrada. No se ha movido ningún correo.")
