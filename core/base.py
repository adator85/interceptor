from subprocess import run, PIPE
import os, threading, time, socket, json, requests
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Engine, Connection, CursorResult
from sqlalchemy.sql import text
from platform import python_version
from typing import Union

class Base:

    __COLORS:dict = {'white': '\033[97m', 
                'green': '\033[92m', 
                'red': '\033[91m',
                'yellow': '\033[93m',
                'reset':'\033[0m'
                }

    def __init__(self) -> None:

        self.VERSION                = '2.0.0'                                   # MAJOR.MINOR.BATCH
        self.CURRENT_PYTHON_VERSION = python_version()                          # Current python version
        self.DATE_FORMAT            = '%Y-%m-%d %H:%M:%S'                       # The date format
        self.HOSTNAME               = socket.gethostname()                      # Hostname of the local machine
        self.IPV4                   = socket.gethostbyname(self.HOSTNAME)       # Local ipv4 of the local machine
        self.PULSE                  = 5                                         # Pulse in seconds
        self.DEBUG                  = False                                     # Debug variable pour afficher les outputs
        self.default_attempt        = 4                                         # Default attempt before jail
        self.default_jail_duration  = 120                                       # Default Duration in seconds before the release
        self.default_ipv4           = '0.0.0.0'                                 # Default ipv4 to be used by Interceptor

        self.api:dict               = {}                                        # Available API's configuration from global.json

        self.default_intc_active    = False                                     # Use head quarter information
        self.default_intc_report    = False                                     # Report to the HQ intrusions
        self.default_intc_timeout   = 5                                         # HQ Timeout

        self.abuseipdb_config:dict          = {}                                # AbuseIPDB Configuration
        self.abuseipdb_status:bool          = False                             # Default abuseipdb status
        self.abuseipdb_report:bool          = False                             # Default abuseipdb report, if config file is set to true then Interceptor will send report intrusion to abuseIPDB
        self.abuseipdb_jail_score:int       = 100                               # Default score for the jail if not set in the configuration
        self.abuseipdb_jail_duration:int    = 600                               # Default duration for abusedbip if not set


        self.lock = threading.RLock()                                           # Define RLock for multithreading
        self.hb_active:bool = True                                              # Define heartbeat variable
        self.running_threads:list[threading.Thread] = []                        # Define running_threads variable

        self.logs_init()                                                        # Init logs directory and log file.
        self.engine, self.cursor = self.db_init()                               # Init Engine & Cursor
        self.__db_create_tables()                                               # Create tables        

        return None

    def get_unixtime(self)->int:
        """
        Cette fonction retourne un UNIXTIME de type 12365456
        Return: Current time in seconds since the Epoch (int)
        """
        unixtime = int( time.time() )
        return unixtime

    def get_datetime(self) -> datetime:

        return datetime.now()

    def get_sdatetime(self) -> str:
        """
        Retourne une date au format string (24-12-2023 20:50:59)
        """
        currentdate = datetime.now().strftime(self.DATE_FORMAT)
        return currentdate

    def convert_to_datetime(self, datetime_text:str) -> datetime:
        """Convertir un datetime de type text en type datetime object

        Args:
            datetime_text (str): la date et l'heure a convertir

        Returns:
            datetime: datetime object
        """
        conveted_datetime = datetime.strptime(datetime_text, self.DATE_FORMAT)

        return conveted_datetime

    def minus_one_hour(self, hours:float) -> str:

        # '17-02-2024 19:26:16'
        current_datetime = datetime.now()
        result_datetime = current_datetime - timedelta(hours=hours)

        result_datetime = result_datetime.strftime(self.DATE_FORMAT)

        return result_datetime

    def add_secondes_to_date(self, date_time:datetime, seconds_duration:int) -> datetime:

        result = date_time + timedelta(seconds=seconds_duration)

        return result

    def db_init(self) -> tuple[Engine, Connection]:
        db_directory = f'db{os.sep}'
        db_full_path = f'{db_directory}software.db'

        if not os.path.exists(f'{db_directory}'):
            os.makedirs(db_directory)
        
        engine = create_engine(f'sqlite:///{db_full_path}', echo=False)
        cursor = engine.connect()

        return engine, cursor

    def db_execute_query(self, query:str, params:dict = {}) -> CursorResult:

        with self.lock:
            insert_query = text(query)
            if not params:
                response = self.cursor.execute(insert_query)
            else:
                response = self.cursor.execute(insert_query, params)

            self.cursor.commit()

            return response

    def __db_create_tables(self) -> None:

        table_logs = f'''CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            datetime TEXT,
            service_id TEXT,
            module_name TEXT,
            ip TEXT,
            keyword TEXT,
            user TEXT
            )
        '''

        table_iptables = f'''CREATE TABLE IF NOT EXISTS iptables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            datetime TEXT,
            module_name TEXT,
            ip TEXT,
            duration INTEGER
            )
        '''

        table_iptables_logs = f'''CREATE TABLE IF NOT EXISTS iptables_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            datetime TEXT,
            module_name TEXT,
            ip TEXT,
            duration INTEGER
            )
        '''

        table_abuseipdb = f'''CREATE TABLE IF NOT EXISTS abuseipdb (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            datetime TEXT,
            country_code TEXT,
            ip TEXT,
            isTor TEXT,
            totalReports INTEGER,
            score INTEGER
            )
        '''

        table_reported_abuseipdb = f'''CREATE TABLE IF NOT EXISTS reported_abuseipdb (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            datetime TEXT,
            reported_datetime TEXT,
            ip TEXT,
            category TEXT,
            comment TEXT
            )
        '''

        self.db_execute_query(table_logs)
        self.db_execute_query(table_iptables)
        self.db_execute_query(table_iptables_logs)
        self.db_execute_query(table_abuseipdb)
        self.db_execute_query(table_reported_abuseipdb)

        return None

    def db_record_ip(self, service_id:str, module_name:str, ip:str, keyword:str, user:str) -> int:

        query = '''INSERT INTO logs (datetime, service_id, module_name, ip, keyword, user) 
                VALUES (:datetime,:service_id, :module_name, :ip, :keyword, :user)
                '''
        mes_donnees = {
                        'datetime': self.get_sdatetime(),
                        'service_id': service_id,
                        'module_name':module_name,
                        'ip': ip,
                        'keyword':keyword,
                        'user':user
                        }

        r = self.db_execute_query(query, mes_donnees)

        return r.rowcount

    def db_record_iptables(self, module_name:str, ip:str, duration:int) -> int:

        query = '''INSERT INTO iptables (datetime, module_name, ip, duration) 
                VALUES (:datetime, :module_name, :ip, :duration)
                '''
        mes_donnees = {
                        'datetime': self.get_sdatetime(),
                        'module_name':module_name,
                        'ip': ip,
                        'duration':duration
                        }

        r = self.db_execute_query(query, mes_donnees)
        return r.rowcount

    def db_record_iptables_logs(self, module_name:str, ip:str, duration:int) -> None:

        query = '''INSERT INTO iptables_logs (datetime, module_name, ip, duration) 
                VALUES (:datetime, :module_name, :ip, :duration)
                '''
        mes_donnees = {
                        'datetime': self.get_sdatetime(),
                        'module_name':module_name,
                        'ip': ip,
                        'duration':duration
                        }

        self.db_execute_query(query, mes_donnees)
        return None

    def db_remove_iptables(self, ip:str) -> None:

        query = '''DELETE FROM iptables WHERE ip = :ip'''

        mes_donnees = {'ip': ip}

        self.db_execute_query(query, mes_donnees)

        return None

    def logs_init(self) -> None:
        """Create logs directory if not available
        """
        logs_directory = f'logs{os.sep}'
        logs_full_path = f'{logs_directory}intercept.log'

        if not os.path.exists(f'{logs_directory}'):
            os.makedirs(logs_directory)
            with open(logs_full_path, 'a+') as log:
                log.write(f'{self.get_sdatetime()} - Interceptor Init logs\n')
        
        return None

    def log_print(self, string:str, color:str = None) -> None:
        """Print logs in the terminal and record it in a file

        Args:
            string (str): the log message
            color (str): the color to be used in the terminal
        """
        reset = self.__COLORS['reset']
        isExist_color = False

        if color is None:
            print(f'{self.get_sdatetime()}: {string}')
        
        for key_color, value_color in self.__COLORS.items():
            if key_color == color:
                print(f'{value_color}{self.get_sdatetime()}: {string}{reset}')
                isExist_color = True
        
        if not isExist_color:
            print(f'{self.get_sdatetime()}: {string}')

        logs_directory = f'logs{os.sep}'
        logs_full_path = f'{logs_directory}intercept.log'
        
        with open(logs_full_path, 'a+') as log:
            log.write(f'{self.get_sdatetime()}: {string}\n')
            log.close()

        return None

    def create_thread(self, func:object, func_args: tuple = ()) -> None:
        try:
            func_name = func.__name__
            # if func_name in self.running_threads:
            #     print(f"HeartBeat is running")
            #     return None

            th = threading.Thread(target=func, args=func_args, name=str(func_name), daemon=True)
            th.start()

            self.running_threads.append(th)
            self.log_print(f"Thread ID : {str(th.ident)} | Thread name : {th.getName()} | Running Threads : {len(threading.enumerate())}", "green")

        except AssertionError as ae:
            self.log_print(f'Assertion Error -> {ae}', 'red')

    def heartbeat(self, beat:float) -> None:

        while self.hb_active:
            time.sleep(beat)
            self.clean_iptables()
        
        return None

    def get_no_filters_files(self) -> int:

        path = f'modules{os.sep}'
        no_files = 0

        list_files_in_directory = os.listdir(path)

        for file in list_files_in_directory:
            if file.endswith('.json'):
                no_files += 1

        return no_files

    def clean_iptables(self) -> None:

        # Récuperer la date de la base de donnée
        # Convertir la date
        # Ajouter la duration
        # si la date + duration > date actuel supprimer l'enregistrement

        query = f'''SELECT ip, datetime, duration, module_name 
                    FROM iptables
                '''
        
        cursorResult = self.db_execute_query(query)
        r = cursorResult.fetchall()

        for result in r:
            db_ip, db_datetime, db_duration, db_module_name = result
            datetime_object = self.convert_to_datetime(db_datetime)
            dtime_final = self.add_secondes_to_date(datetime_object, db_duration)

            if self.get_datetime() > dtime_final:
                self.db_remove_iptables(db_ip)
                self.ip_tables_remove(db_ip)
                self.log_print(f'{db_module_name} - "{db_ip}" - released from jail', 'green')

    def clean_db_logs(self) -> None:
        """Clean logs that they have more than 24 hours
        """

        query = "DELETE FROM logs WHERE ip = :ip"
        mes_donnees = {'ip': self.default_ipv4}
        default_ip_request = self.db_execute_query(query,mes_donnees)

        query = '''DELETE FROM logs WHERE datetime <= :datetime'''
        mes_donnees = {'datetime':self.minus_one_hour(24)}
        r_datetime = self.db_execute_query(query, mes_donnees)

        query = f'''DELETE FROM abuseipdb WHERE score < :score and datetime <= :datetime'''
        mes_donnees = {'datetime':self.minus_one_hour(24), 'score': self.abuseipdb_jail_score}
        r_abuseipdb = self.db_execute_query(query, mes_donnees)

        affected_rows = r_datetime.rowcount
        affected_rows_abuseipdb = r_abuseipdb.rowcount
        affected_rows_default_ipv4 = default_ip_request.rowcount
        affected = affected_rows + affected_rows_abuseipdb + affected_rows_default_ipv4

        if affected > 0:
            self.log_print(f'clean_db_logs - Deleted : Logs {str(affected_rows)} - AbuseIPDB {str(affected_rows_abuseipdb)} - Default ip {affected_rows_default_ipv4}','green')

        return None

    def ip_tables_add(self, module_name:str, ip:str, duration_seconds:int) -> int:

        if self.ip_tables_isExist(ip):
            return 0

        system_command = '/sbin/iptables -A INPUT -s {} -j REJECT'.format(ip)
        os.system(system_command)
        rowcount = self.db_record_iptables(module_name, ip, duration_seconds)
        self.db_record_iptables_logs(module_name, ip, duration_seconds)
        return rowcount

    def ip_tables_remove(self, ip:str) -> None:

        system_command = '/sbin/iptables -D INPUT -s {} -j REJECT'.format(ip)
        os.system(system_command)
        return None

    def ip_tables_reset(self) -> None:

        system_command = '/sbin/iptables -F'
        os.system(system_command)
        return None

    def ip_tables_isExist(self, ip:str) -> bool:
        """Vérifie si une ip existe dans iptables

        Args:
            ip (str): l'adresse ip

        Returns:
            bool: True si l'ip existe déja
        """
        
        # check_rule = run(['/sbin/iptables','-C','INPUT','-s',ip,'-j','REJECT'],stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
        check_rule = run(['/sbin/iptables','-C','INPUT','-s',ip,'-j','REJECT'],stdout=PIPE, stderr=PIPE).returncode == 0
        response = False

        if check_rule:
            response = True

        return response

    def check_endpoint_abuseipdb(self, parsed_api:dict, ip_to_check:str) -> Union[dict, None]:

        api_name = 'abuseipdb'

        if not api_name in parsed_api:
            return None
        elif not self.abuseipdb_status:
            return None
        elif ip_to_check == self.default_ipv4:
            return None

        api_url = parsed_api[api_name]['url']
        api_key = parsed_api[api_name]['api_key']

        if api_key == '' or api_url == '':
            self.log_print('AbuseIPDB - API Key or API ENDPOINT Error : empty','red')
            return None

        # Defining the api-endpoint
        url = f'{api_url}check'

        querystring = {
            'ipAddress': ip_to_check,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring, timeout=5)

            # Formatted output
            req = json.loads(response.text)
            # req = json.dumps(decodedResponse, sort_keys=True, indent=4)
            if 'errors' in req:
                self.log_print(f'API Error : {req["errors"][0]["detail"]}','red')
                return None

            ip = req['data']['ipAddress']
            country = req['data']['countryCode']
            isTor = req['data']['isTor']
            totalReports = req['data']['totalReports']
            score = req['data']['abuseConfidenceScore']

            mes_donnees = {'datetime': self.get_sdatetime(), 'country_code': country,'ip': ip,'isTor':isTor,'totalReports': totalReports,'score': score}
            r = self.db_execute_query('INSERT INTO abuseipdb (datetime, country_code, ip, isTor, totalReports, score) VALUES (:datetime,:country_code, :ip, :isTor, :totalReports, :score)', mes_donnees)
            if r.rowcount > 0:
                self.log_print(f'AbuseIPDB - new ip recorded : IP: "{ip}" - Score: {score}','green')
            resp:dict = dict(req)
            return resp

        except KeyError as ke:
            self.log_print(f'API Error KeyError : {ke}','red')
        except requests.ReadTimeout as timeout:
            self.log_print(f'API Error Timeout : {timeout}','red')
        except requests.ConnectionError as ConnexionError:
            self.log_print(f'API Connection Error : {ConnexionError}','red')

    def get_local_abuseipdb_score(self, ip_address:str) -> tuple[int, int, int]:
        """Return local information stored in the database
        abuseipdb table already contain some fetched ip

        Args:
            ip_address (str): Ip to analyse

        Returns:
            tuple[int, int, int]: isTor, totalReports, score
        """
        response:tuple = ()
        query = 'SELECT isTor, totalReports, score FROM abuseipdb WHERE ip = :ip'
        mes_donnees = {'ip': ip_address}

        res_sql = self.db_execute_query(query, mes_donnees)

        fetch_result = res_sql.fetchone()        
        
        if not fetch_result is None:
            isTor = int(fetch_result.isTor)
            totalReports = int(fetch_result.totalReports)
            score = int(fetch_result.score)
            
            response = (isTor, totalReports, score)       

        return response

    def report_to_abuseipdb(self, ip_address:str, attack_datetime:str, category:list, comment:str) -> None:
        """_summary_

        Args:
            ip_address (str): _description_
            attack_datetime (str): _description_
            category (list): _description_
            comment (str): _description_

        Returns:
            _type_: _description_
        """
        try:

            api_name        = 'abuseipdb'

            if not api_name in self.abuseipdb_config:
                return None
            elif not self.abuseipdb_status:
                return None
            elif ip_address == self.default_ipv4:
                return None

            api_url         = self.abuseipdb_config[api_name]['url']
            api_key         = self.abuseipdb_config[api_name]['api_key']
            
            if api_url == '' or api_key == '':
                self.log_print('AbuseIPDB - API Key or API ENDPOINT Error : empty','red')
                return None
            
            # Create category section
            category_ = ''
            count = 0
            for cat in category:
                count += 1
                category_ += f'{cat}'
                if count < len(category):
                    category_ += ','

            # Defining the api-endpoint
            url = f'{api_url}report'

            converted_attack_datetime = datetime.strptime(attack_datetime, "%d-%m-%Y %H:%M:%S")
            current_timezone = converted_attack_datetime.astimezone().tzinfo
            converted_attack_datetime = converted_attack_datetime.replace(tzinfo=current_timezone)
            timestamp_attack_datetime = converted_attack_datetime.isoformat()

            # String holding parameters to pass in json format
            params = {
                'ip':ip_address,
                'categories':category_,
                'comment':comment,
                'timestamp':timestamp_attack_datetime
            }

            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }

            with requests.request(method='POST', url=url, headers=headers, params=params, timeout=2) as response:

                req = json.loads(response.text)
                if 'errors' in req:
                    self.log_print(f'API Error : {req["errors"]}','red')
                    return None

                abuseipdb_ipAddress = req['data']['ipAddress']
                abuseipdb_score     = req['data']['abuseConfidenceScore']

                query_reported_abuseipdb = '''INSERT INTO reported_abuseipdb (datetime, reported_datetime, ip, category, comment) 
                                            VALUES 
                                            (:datetime, :reported_datetime, :ip, :category, :comment)
                                            '''
                mes_donnees = {'datetime': self.get_sdatetime(), 'reported_datetime': attack_datetime,'ip': ip_address, 'category':category_,'comment': comment}
                r = self.db_execute_query(query_reported_abuseipdb, mes_donnees)
                if r.rowcount > 0:
                    self.log_print(f'AbuseIPDB - REPORT SENT - IP: {abuseipdb_ipAddress} | Updated score : {str(abuseipdb_score)}','green')

            return None

        except KeyError as ke:
            self.log_print(f'API Error KeyError : {ke}','red')
        except requests.ReadTimeout as timeout:
            self.log_print(f'API Error Timeout : {timeout}','red')
        except requests.ConnectionError as ConnexionError:
            self.log_print(f'API Connection Error : {ConnexionError}','red')

    def get_information_from_HQ(self, ip_address: str) -> Union[dict, None]:

        try:
            api_name        = 'intc_hq'

            if not api_name in self.api:
                return None
            elif not self.api[api_name]['active']:
                return None
            elif not self.api[api_name]['report']:
                return None
            elif ip_address == self.default_ipv4:
                return None

            url = f"{self.api[api_name]['url']}check/" if 'url' in self.api[api_name] else None
            api_key = self.api[api_name]['api_key'] if 'api_key' in self.api[api_name] else None

            if url is None:
                return None

            url = url + ip_address

            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'user-agent': 'Interceptor Client',
                'Key': api_key
            }

            response = requests.request(method='GET', url=url, headers=headers, timeout=self.default_intc_timeout)

            # Formatted output
            req = json.loads(response.text)

            if 'code' in req:
                if not req['error']:
                    self.log_print(f"INTC_HQ RECEIVE INFORMATION - {ip_address} --> {str(req['code'])} {req['message']}", "green")
                else:
                    self.log_print(f"INTC_HQ RECEIVE INFORMATION - {ip_address} --> {str(req['code'])} {req['message']}", "red")

            return req

        except KeyError as ke:
            self.log_print(f'API Error KeyError : {ke}','red')
        except requests.ReadTimeout as timeout:
            self.log_print(f'API Error Timeout : {timeout}','red')
        except requests.ConnectionError as ConnexionError:
            if self.DEBUG:
                self.log_print(f'API Connection Error : {ConnexionError}','red')

        return None

    def report_to_HQ(self, intrusion_datetime:str, intrusion_detail:str, ip_address:str, intrusion_service_id:str) -> None:

        try:
            api_name        = 'intc_hq'

            if not api_name in self.api:
                return None
            elif not self.api[api_name]['active']:
                return None
            elif not self.api[api_name]['report']:
                return None
            elif ip_address == self.default_ipv4:
                return None

            url = f"{self.api[api_name]['url']}report/" if 'url' in self.api[api_name] else None
            api_key = self.api[api_name]['api_key'] if 'api_key' in self.api[api_name] else None

            if url is None:
                return None

            querystring = {
                'intrusion_datetime': intrusion_datetime,
                'intrusion_detail': intrusion_detail,
                'intrusion_service_id': str(intrusion_service_id),
                'ip_address': ip_address,
                'reported_hostname': self.HOSTNAME
            }

            headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'user-agent': 'Interceptor Client',
                'Key': api_key
            }

            response = requests.request(method='POST', url=url, headers=headers, timeout=self.default_intc_timeout, json=querystring)

            # Formatted output
            req = json.loads(response.text)

            if 'code' in req:
                if req['code'] == 200:
                    self.log_print(f"INTC_HQ REPORTED - {ip_address} --> {str(req['code'])} {req['message']}", "green")
                else:
                    self.log_print(f"INTC_HQ RESPONSE - {ip_address} - {str(req['code'])} {req['message']}", "red")

            return None

        except KeyError as ke:
            self.log_print(f'API Error KeyError : {ke}','red')
        except requests.ReadTimeout as timeout:
            self.log_print(f'API Error Timeout : {timeout}','red')
        except requests.ConnectionError as ConnexionError:
            if self.DEBUG:
                self.log_print(f'API Connection Error : {ConnexionError}','red')

        return None
