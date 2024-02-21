from subprocess import run, PIPE
import os, threading, time, socket
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Engine, Connection, CursorResult
from sqlalchemy.sql import text

class Base:

    __COLORS = {'white': '\033[97m', 
                'green': '\033[92m', 
                'red': '\033[91m', 
                'reset':'\033[0m'
                }

    def __init__(self) -> None:

        self.VERSION  = '0.0.1'                                 # MAJOR.MINOR.BATCH
        self.HOSTNAME = socket.gethostname()                    # Hostname of the local machine
        self.IPV4     = socket.gethostbyname(self.HOSTNAME)     # Local ipv4 of the local machine
        self.PULSE    = 5                                       # Pulse in seconds 

        self.lock = threading.RLock()                           # Define RLock for multithreading
        self.hb_active:bool = True                              # Define heartbeat variable
        self.running_threads:list[threading.Thread] = []        # Define running_threads variable
        self.engine, self.cursor = self.db_init()               # Init Engine & Cursor
        self.__db_create_tables()                               # Create tables        

        return None

    def get_datetime(self) -> datetime:

        return datetime.now()

    def get_sdatetime(self) -> str:
        """
        Retourne une date au format string (24-12-2023 20:50:59)
        """
        currentdate = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        return currentdate

    def convert_to_datetime(self, datetime_text:str) -> datetime:
        """Convertir un datetime de type text en type datetime object

        Args:
            datetime_text (str): la date et l'heure a convertir

        Returns:
            datetime: datetime object
        """
        format = '%d-%m-%Y %H:%M:%S'

        conveted_datetime = datetime.strptime(datetime_text, format)

        return conveted_datetime

    def minus_one_hour(self, hours:float) -> str:

        # '17-02-2024 19:26:16'
        current_datetime = datetime.now()
        result_datetime = current_datetime - timedelta(hours=hours)

        result_datetime = result_datetime.strftime('%d-%m-%Y %H:%M:%S')

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
            process_id TEXT,
            process TEXT,
            ip TEXT,
            keyword TEXT,
            user TEXT
            )
        '''

        table_iptables = f'''CREATE TABLE IF NOT EXISTS iptables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            datetime TEXT,
            process TEXT,
            ip TEXT,
            duration INTEGER
            )
        '''

        self.db_execute_query(table_logs)
        self.db_execute_query(table_iptables)

        return None

    def db_record_ip(self, process_id:str, process:str, ip:str, keyword:str, user:str) -> None:

        query = '''INSERT INTO logs (datetime, process_id, process, ip, keyword, user) 
                VALUES (:datetime,:process_id, :process, :ip, :keyword, :user)
                '''
        mes_donnees = {
                        'datetime': self.get_sdatetime(),
                        'process_id': process_id,
                        'process':process,
                        'ip': ip,
                        'keyword':keyword,
                        'user':user
                        }

        self.db_execute_query(query, mes_donnees)
        return None

    def db_record_iptables(self, process:str, ip:str, duration:int) -> None:

        query = '''INSERT INTO iptables (datetime, process, ip, duration) 
                VALUES (:datetime, :process, :ip, :duration)
                '''
        mes_donnees = {
                        'datetime': self.get_sdatetime(),
                        'process':process,
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

    def log_print(self, string:str, color:str) -> None:

        reset = self.__COLORS['reset']
        find_color = False
        
        for key_color, value_color in self.__COLORS.items():
            if key_color == color:
                print(f'{value_color}{self.get_sdatetime()}: {string}{reset}')
                find_color = True
        
        if not find_color:
            print(f'{self.get_sdatetime()}: {string}')

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

        query = f'''SELECT ip, datetime, duration 
                    FROM iptables
                '''
        
        cursorResult = self.db_execute_query(query)
        r = cursorResult.fetchall()

        for result in r:
            db_ip, db_datetime, db_duration = result
            datetime_object = self.convert_to_datetime(db_datetime)
            dtime_final = self.add_secondes_to_date(datetime_object, db_duration)

            if self.get_datetime() > dtime_final:
                self.db_remove_iptables(db_ip)
                self.ip_tables_remove(db_ip)
                self.log_print(f'Ip "{db_ip}" - released from jail', 'green')

    def clean_db_logs(self) -> None:
        query = '''DELETE FROM logs WHERE datetime <= :datetime'''
        mes_donnees = {'datetime':self.minus_one_hour(24)}
        self.db_execute_query(query, mes_donnees)

        return None

    def ip_tables_add(self, process:str, ip:str, duration_seconds:int) -> None:

        if self.ip_tables_isExist(ip):
            return None
        
        system_command = '/sbin/iptables -A INPUT -s {} -j REJECT'.format(ip)
        os.system(system_command)
        self.db_record_iptables(process, ip, duration_seconds)
        return None

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