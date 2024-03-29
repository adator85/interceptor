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
            # Activate thread reporting to HQ
            pass 

        return None

    def cron(self, func:object, timer_seconds:int) -> None:

        timer = timer_seconds

        while True:
            if self.Base.DEBUG:
                self.Base.log_print(f'CRON - "{func.__name__}" - starting new job - next scheduled job in {str(timer)} Seconds','green')
            func()
            time.sleep(timer)

    def report_to_HQ_thread(self) -> None:

        query_log = 'SELECT id, datetime, service_id, ip FROM logs'

        return None