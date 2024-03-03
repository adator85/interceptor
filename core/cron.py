import time
from core import base, parser

class Cron:
    """### Cron class
    ++ Cron is called from main.py after parser.py
    + main.py:
        - base.py
        - parser.py
        - cron.py
        - interceptprocess.py
    + It create threads heartbeat every (self.Base.PULSE) seconds to run
    periodic actions
    + It trigger every hour (self.Base.clean_db_logs) method via cron
    + It trigger (self.init_abuseipdb) method via cron
    + It trigger (self.report_to_abuseipdb) method via cron
    """

    def __init__(self, Base:base.Base, Parser:parser.Parser) -> None:
        """### Cron class
        - It create threads heartbeat every (self.Base.PULSE) seconds to run
        periodic actions
        - It trigger every hour (self.Base.clean_db_logs) method via cron
        - It trigger (self.init_abuseipdb) method via cron
        - It trigger (self.report_to_abuseipdb) method via cron

        Args:
            Base (base.Base): Existing Basic Interceptor class
            Parser (parser.Parser): Existing instance of Parser class

        Returns:
            None: No returns
        """
        self.Base = Base
        self.Parser = Parser

        return None

    def init(self) -> None:

        # Initialiser heartbeat
        self.Base.create_thread(self.Base.heartbeat, (self.Base.PULSE, ))
        self.Base.create_thread(self.cron, (self.Base.clean_db_logs, 60 * 60))

        if self.Base.abuseipdb_status:
            self.Base.create_thread(self.cron, (self.init_abuseipdb, 20))
        
        if self.Base.abuseipdb_report and self.Base.abuseipdb_status:
            self.Base.create_thread(self.cron, (self.report_to_abuseipdb, 600))

        return None

    def cron(self, func:object, timer_seconds:int) -> None:
        """Execute a method every X seconds

        Args:
            func (object): The method/function to call
            timer_seconds (int): The time in seconds between every execution
        """
        timer = timer_seconds

        while True:
            if self.Base.DEBUG:
                self.Base.log_print(f'CRON - "{func.__name__}" - starting new job - next scheduled job in {str(timer)} Seconds','green')
            func()
            time.sleep(timer)

    def init_abuseipdb(self):

        # Verifier si l'ip est disponible dans la base abuseipdb
        # Si n'existe pas alors verifier et récuperer le score avec check_endpoint
        # while True:

        query_ip_not_analysed = '''SELECT l.ip as ip FROM logs l 
                                LEFT JOIN abuseipdb ipdb ON ipdb.ip = l.ip 
                                WHERE ipdb.ip is NULL
                                GROUP BY l.ip
                                ORDER BY l.id DESC;
                                '''
        exec = self.Base.db_execute_query(query_ip_not_analysed)
        req = exec.fetchall()

        for r in req:
            ip = r[0]

            if ip != self.Base.default_ipv4:
                self.Base.log_print(f'AbuseIPDB - Waiting for information about IP : {ip}','yellow')
                self.Base.check_endpoint_abuseipdb(self.Parser.global_api, ip)

                # wait for 10 seconds before sending a new ip for verification
                time.sleep(10)
        
        if self.Base.DEBUG:
            self.Base.log_print(f'AbuseIPDB - CRON - end of the "{self.init_abuseipdb.__name__}" job!','yellow')

    def report_to_abuseipdb(self):

        query_logs = '''SELECT MAX(id) as id, ip, module_name, max(datetime) as reported_datetime, service_id FROM logs                                 
                                GROUP BY module_name, ip, service_id
                                ORDER BY id DESC
                                '''
        fetch_logs = self.Base.db_execute_query(query_logs)

        # Fetch the id of the ip reported at a specific datetime
        query_reported_abuseipdb = '''SELECT id FROM reported_abuseipdb WHERE reported_datetime = :datetime and ip = :ip'''

        query_check_reported_date = '''SELECT MAX(datetime) as latest_reported_datetime FROM reported_abuseipdb WHERE ip = :ip GROUP BY ip'''
        
        categories = {'sshd': [22, 18]}
        category:list = []

        for log in fetch_logs.fetchall():
            db_id, db_ip, db_module_name, db_reported_datetime, db_service_id = log
            
            # Get keyword attack
            get_keyword_query = 'SELECT keyword FROM logs WHERE id = :id'
            get_keyword_cursor = self.Base.db_execute_query(get_keyword_query, {'id': db_id})
            keyword = get_keyword_cursor.fetchone()
            
            _15_minutes_minus = self.Base.convert_to_datetime(self.Base.minus_one_hour(0.30))
            mes_donnees_check_ip = {'datetime': db_reported_datetime, 'ip': db_ip}
            fetch_query = self.Base.db_execute_query(query_reported_abuseipdb, mes_donnees_check_ip)
            
            fetch_last_date = self.Base.db_execute_query(query_check_reported_date, {'ip': db_ip})
            result_latest_date = fetch_last_date.fetchone()
            
            allow_report = True

            if not result_latest_date is None:
                latest_date_recorded = self.Base.convert_to_datetime(result_latest_date.latest_reported_datetime)
                if latest_date_recorded > _15_minutes_minus:
                    allow_report = False

            # If ip and datetime is not found in reported_abuseipdb then send report
            if fetch_query.fetchone() is None and allow_report:
                comment = f'Inteceptor Intrusion Detector: {keyword.keyword} on {db_module_name} module PID: ({db_service_id})'
                
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

        if self.Base.DEBUG:
            self.Base.log_print(f'AbuseIPDB - CRON - end of the "{self.report_to_abuseipdb.__name__}" job!','yellow')

        pass