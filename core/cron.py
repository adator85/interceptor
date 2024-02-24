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
                self.Base.create_thread(self.cron, (self.report_to_abuseipdb, 600))

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
        
        self.Base.log_print(f'AbuseIPDB - CRON - {self.init_abuseipdb.__name__} new Itteration','yellow')

    def report_to_abuseipdb(self):

        query_fetch_ip = '''SELECT MAX(id) as id, ip, module_name, max(datetime) as reported_datetime, service_id FROM logs                                 
                                GROUP BY module_name, ip, service_id
                                ORDER BY id
                                '''
        fetch_result = self.Base.db_execute_query(query_fetch_ip)

        query_check_ip = '''SELECT id FROM reported_abuseipdb WHERE reported_datetime = :datetime and ip = :ip'''

        query_check_reported_date = '''SELECT MAX(datetime) as latest_reported_datetime FROM reported_abuseipdb WHERE ip = :ip GROUP BY ip'''
        
        categories = {'sshd': [22, 18]}
        category:list = []

        for infos in fetch_result.fetchall():
            db_id, db_ip, db_module_name, db_reported_datetime, db_service_id = infos
            
            _15_minutes_minus = self.Base.convert_to_datetime(self.Base.minus_one_hour(0.30))
            mes_donnees_check_ip = {'datetime': db_reported_datetime, 'ip': db_ip, '_15_minutes_minus': _15_minutes_minus}
            fetch_query = self.Base.db_execute_query(query_check_ip, mes_donnees_check_ip)
            
            fetch_last_date = self.Base.db_execute_query(query_check_reported_date, {'ip': db_ip})
            result_latest_date = fetch_last_date.fetchone()
            
            allow_report = True

            if not result_latest_date is None:
                latest_date_recorded = self.Base.convert_to_datetime(result_latest_date.latest_reported_datetime)
                if latest_date_recorded > _15_minutes_minus:
                    allow_report = False

            # If ip and datetime is not found in reported_abuseipdb then send report
            if fetch_query.fetchone() is None and allow_report:
                comment = f'Inteceptor Intrusion Detector: Authentication failed on {db_module_name} module PID: ({db_service_id})'
                
                if db_module_name in categories:
                    category = categories[db_module_name]
                else:
                    category = [18]

                self.Base.log_print(f'AbuseIPDB - Currently Reporting the ip : {db_ip}','yellow')
                self.Base.report_to_abuseipdb(db_ip, db_reported_datetime, category , comment)
                time.sleep(20)
            else:
                if self.Base.DEBUG:
                    self.Base.log_print(f'AbuseIPDB - Attack already reported to abuseipdb : {db_ip}','yellow')

        self.Base.log_print(f'AbuseIPDB - CRON - {self.report_to_abuseipdb.__name__} new Itteration','yellow')
        pass