import time
from core import base, parser

class Cron:


    def __init__(self, Base:base.Base, Parser:parser.Parser) -> None:

        self.Base = Base
        self.Parser = Parser

        return None

    def init(self) -> None:

        intc_hq_status = self.Base.api['intc_hq']['active'] if 'intc_hq' in self.Base.api else False
        intc_hq_report = self.Base.api['intc_hq']['report'] if 'intc_hq' in self.Base.api else False

        # Initialiser heartbeat
        self.Base.create_thread(self.Base.heartbeat, func_args=(self.Base.PULSE, ), func_name='Heartbeat')
        self.Base.create_thread(self.cron, func_args=(self.Base.clean_db_logs, 60 * 60), func_name='clean_db_logs')

        if intc_hq_status and intc_hq_report:
            # Say first hello to HQ
            self.Base.say_hello_to_hq()

            # Activate thread reporting to HQ
            self.Base.create_thread(func=self.cron, 
                                    func_args=(self.Base.thread_report_to_HQ_v2, self.Base.hq_communication_freq), 
                                    func_name='Interact_with_HQ'
                                    )

        return None

    def cron(self, func:object, timer_seconds:int) -> None:

        timer = timer_seconds

        while True:
            self.Base.logs.debug(f'"{func.__name__}" - Running Cron Every {str(timer)} Seconds')
            func()
            time.sleep(timer)
