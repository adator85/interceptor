import time
from core.installation import Install

def main():
    '''Interceptor main program
    '''
    Install()   # Run installation if needed

    from core.base import Base
    from core.parser import Parser
    from core.cron import Cron
    from core.interceptprocess import InterceptProcess

    BaseInstance = Base()                                           # Initiat the main class
    ParserInstance = Parser(BaseInstance)                           # Initiat the parser class
    CronInstance = Cron(BaseInstance, ParserInstance)               # Initial the cron class
    CronInstance.init()                                             # Start cron jobs
    IProcInstance = InterceptProcess(ParserInstance, BaseInstance)  # Start SubProcesses

    try:

        while BaseInstance.hb_active:
            time.sleep(5)

    finally:
        for subprocess in IProcInstance.subprocess:
            print(f'Terminate subprocess {subprocess}')
            subprocess.terminate()

if __name__ == "__main__":
    main()