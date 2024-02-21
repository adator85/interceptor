from core.installation import Install

Install()   # Run installation if needed

from subprocess import Popen, PIPE
from core.intercept import Intercept

DEBUG = False

def process_journalctl_output(output:str):
    # Fonction de traitement de la sortie de journalctl

    if DEBUG:
        print(output)

# Exécute journalctl -f en arrière-plan
process = Popen(['journalctl', '-f'], stdout=PIPE, stderr=PIPE)

try:
    ExecIntercept = Intercept()                # Creation d'une instance de Intercept

    while True:
        # Lire une ligne de la sortie de journalctl
        output = process.stdout.readline().decode('utf-8').strip()
        if output:
            # Traitement de la ligne de sortie
            ExecIntercept.run_process(output)
            process_journalctl_output(output)


except KeyboardInterrupt:
    # Arrêt propre lorsque l'utilisateur appuie sur Ctrl+C
    process.terminate()


