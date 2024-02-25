import time
from core.installation import Install

def main():
    Install()   # Run installation if needed

    from core.base import Base
    from core.parser import Parser
    from core.cron import Cron
    from core.interceptprocess import InterceptProcess

    BaseInstance = Base()
    ParserInstance = Parser(BaseInstance)
    CronInstance = Cron(BaseInstance, ParserInstance)
    CronInstance.init()
    IProcInstance = InterceptProcess(ParserInstance, BaseInstance)

    try:    

        while BaseInstance.hb_active:
            time.sleep(5)

    finally:
        for subprocess in IProcInstance.subprocess:
            print(f'Terminate subprocess {subprocess}')
            subprocess.terminate()  

if __name__ == "__main__":
    main()