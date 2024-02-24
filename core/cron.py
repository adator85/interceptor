import time
from core import base, parser

class Cron:


    def __init__(self, Base:base.Base, Parser:parser.Parser) -> None:

        self.Base = Base
        self.Parser = Parser

        return None

    def init(self) -> None:
        
        # Initialiser heartbeat
        self.Base.create_thread(self.Base.heartbeat, (self.Base.PULSE, ))
        self.Base.create_thread(self.cron, (self.Base.clean_db_logs, 60 * 60))
        
        # self.Base.create_thread(self.init_abuseipdb)
        if 'abuseipdb' in self.Parser.global_api:
            if 'active' in self.Parser.global_api['abuseipdb'] and self.Parser.global_api['abuseipdb']['active']:
                self.Base.create_thread(self.cron, (self.init_abuseipdb, 120))

        return None

    def cron(self, func:object, timer_seconds:int) -> None:

        timer = timer_seconds

        while True:
            self.Base.log_print(f'CRON - "{func.__name__}" - Next round in {str(timer)} Seconds','green')
            func()
            time.sleep(timer)

    def init_abuseipdb(self):

        # Verifier si l'ip est disponible dans la base abuseipdb
        # Si n'existe pas alors verifier et récuperer le score avec check_endpoint
        # while True:
        query_search_abuseipdb = 'SELECT id FROM abuseipdb WHERE ip = :ip'

        query = 'SELECT ip FROM logs group by ip ORDER BY id DESC'
        exec = self.Base.db_execute_query(query)

        req = exec.fetchall()
        for r in req:
            ip = r[0]
            mes_donnees = {'ip': ip}
            search_ip = self.Base.db_execute_query(query_search_abuseipdb, mes_donnees)
            if search_ip.fetchone() is None: # Ip n'existe pas
                if ip != self.Base.default_ipv4:
                    self.Base.log_print(f'AbuseIPDB - Waiting for information about IP : {ip}','yellow')
                    self.Base.check_endpoint_abuseipdb(self.Parser.global_api, ip)
                    # wait for 2 minutes before sending a new ip for verification
                    time.sleep(20)
            else:
                if self.Base.DEBUG:
                    self.Base.log_print(f'AbuseIPDB - Ip already exist in the database : {ip}','yellow')
        
        self.Base.log_print(f'AbuseIPDB - CRON - New Itteration','yellow')
        #    time.sleep(60)
