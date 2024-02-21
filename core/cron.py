import time
from core import base

class Cron:


    def __init__(self, Base:base.Base) -> None:

        self.Base = Base

        return None

    def init(self) -> None:
        # Initialiser heartbeat
        self.Base.create_thread(self.Base.heartbeat, (self.Base.PULSE, ))
        self.Base.create_thread(self.cron, (self.Base.clean_db_logs, 60 * 60))

        return None

    def cron(self, func:object, timer_seconds:int) -> None:

        timer = timer_seconds

        while True:
            time.sleep(timer)
            func()
            self.Base.log_print(f'Running Cron {func.__name__} every {str(timer)} Seconds','green')
