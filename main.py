import time
from core.installation import Install

def main():
    Install()   # Run installation if needed

    from core.base import Base
    from core.parser import Parser
    from core.cron import Cron
    from core.interceptprocess import InterceptProcess

    BaseInstance = Base()                                           # Init the base class
    ParserInstance = Parser(BaseInstance)                           # Init the parser class
    CronInstance = Cron(BaseInstance, ParserInstance)               # Init the cron class
    CronInstance.init()                                             # Start cron jobs
    IProcInstance = InterceptProcess(BaseInstance, ParserInstance)  # Start SubProcesses

    try:

        while BaseInstance.hb_active:
            time.sleep(5)

    except KeyboardInterrupt as ke:
        BaseInstance.logs.info(f"|| System interrupted by the user ||")
        print("|| System interrupted by the user ||")

    finally:
        for subprocess in IProcInstance.subprocess:
            BaseInstance.logs.debug(f'Terminate subprocess {subprocess}')
            subprocess.terminate()

        BaseInstance.ip_tables_reset()

if __name__ == "__main__":
    main()