import re
from core import base, parser, cron

class Intercept:

    __PATTERN_IPV4 = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$'
    __PATTERN_IPV6 = r'([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})'

    default_ip = '0.0.0.0'
    is_process:bool = False

    def __init__(self) -> None:
        
        self.Base = base.Base()                      # Création d'une instance Base()
        self.Parser = parser.Parser(self.Base)       # Création d'une instance Parser()
        self.Cron = cron.Cron(self.Base)             # Création d'une instance Cron()

        self.intercept_initialization()              # Initialisation d'Interceptor
        self.Base.clean_iptables()                   # Premiere initialisation vider les ban dans la base de données
        self.Cron.init()                             # Initialiser les threads

        return None

    def intercept_initialization(self) -> None:

        message = '#    Starting Interceptor Security    '
        hn  = f'#    Hostname       : {self.Base.HOSTNAME}\n'
        hn += f'#    IPV4           : {self.Base.IPV4}\n'
        hn += f'#    Version        : {self.Base.VERSION}\n'
        hn += f'#    Modules loaded :\n'
        
        for file in self.Parser.filenames:
            hn += f'#                    - {file}\n'
        
        taille = len(message) + 5

        print('#' * taille)
        print(message)
        print(hn)
        print('#' * taille)

        return None

    def run_process(self, output:str) -> None:

        for proc in self.Parser.process:
            process = re.search(self.Parser.all_modules[proc]['rgx_process_name'], output)

            if process:
                self.is_process = True
                self.record_entry(output, proc)

        return None
    
    def record_entry(self, output:str, process:str) -> None:

        ip = ''
        ip_exceptions:list = []
        ipv4_address = self.get_ipv4_address(output)
        ipv6_address = self.get_ipv6_address(output)
        if not ipv4_address is None:
            ip = ipv4_address
        elif not ipv6_address is None:
            ip = ipv6_address
        else:
            ip = self.default_ip

        user = self.get_users_sshd_attempt(output)
        process_id = self.get_process_id(output)
        modules:dict[any, dict] = self.Parser.all_modules
        
        # Charger les exceptions du process en cours
        for key, exception in modules[process].items():
            if type(exception) == list and key == 'exceptions':
                for ip_exception in exception:
                    ip_exceptions.append(ip_exception)

        # Charger les filtres du process en cours
        for key, filters in modules[process].items():
            if type(filters) == dict and key == 'filters':
                for filter_name, filter_value in filters.items():
                    lookup = re.search(filter_value, output)
                    if lookup:
                        # Exception ne sera enregistrer dans la base de données.
                        if not ip in ip_exceptions:
                            self.Base.db_record_ip(process_id, process, ip, filter_name, user)
                            self.Base.log_print(f'{process} - {filter_name} - {process_id} - {ip} - {user} - recorded', 'white')
                            self.execute_action(ip)
       
        return None

    def execute_action(self, received_ip:str) -> None:
        """Executer un ban au niveau de iptables si les conditions sont réunies

        Returns:
            None: aucun retour requis
        """
        try:
            for process in self.Parser.process:
                query = f'''SELECT a.ip as "ip_address", count(DISTINCT(a.process_id)) as "NoAction" 
                            FROM logs as a 
                            WHERE a.process = :process and a.ip = :ip
                            GROUP BY a.ip
                        '''
                mes_donnees = {'process': process, 'ip': received_ip}

                # so far "actions": {'attempt': 4}
                sys_attempt = self.Parser.all_modules[process]['actions']['attempt']
                sys_ban_duration = int(self.Parser.all_modules[process]['actions']['ban_duration'])

                cursorResult = self.Base.db_execute_query(query, mes_donnees)
                r = cursorResult.fetchall()

                for results_ip in r:
                    db_ip, db_attempt = results_ip
                    if db_attempt >= sys_attempt:
                        self.Base.ip_tables_add(process, db_ip, sys_ban_duration)
                        self.Base.log_print(f'{db_ip} - duration: {str(sys_ban_duration)} seconds', 'red')
                    
                    self.Base.clean_iptables()

            return None

        except KeyError as ke:
            self.Base.log_print(f'keyError {process} - {__name__} - {self.execute_action.__name__}: key {ke} is not available', 'red')

    def get_process_id(self, output:str) -> int:
        """Retourn le process id

        Args:
            output (str): journalctl output

        Returns:
            int: process id
        """
        process_id = 0                  # Init process id
        
        for proc in self.Parser.process:
            pattern_process_id = self.Parser.all_modules[proc]['rgx_process_id']
            lookup_process_id = re.search(pattern_process_id, output)
            if lookup_process_id:
                list_search = list(lookup_process_id.groups())
                process_id = list_search[0]

        return process_id
    
    def get_ipv4_address(self, output:str) -> str | None:
        """Retourn l'adresse ip si disponible

        Args:
            output (str): journalctl output

        Returns:
            str: ip address (IPV4)
        """
        ip_address = None                  # Init ip address
        
        lookup_ip_address = re.search(self.__PATTERN_IPV4, output)
        if lookup_ip_address:
            list_search = list(lookup_ip_address.groups())
            ip_address = list_search[0]

        return ip_address
    
    def get_ipv6_address(self, output:str) -> str | None:
        """Retourn l'adresse ip si disponible

        Args:
            output (str): journalctl output

        Returns:
            str: ip address (IPV6)
        """
        ip_address = None                  # Init ip address
        
        lookup_ip_address = re.search(self.__PATTERN_IPV6, output)
        if lookup_ip_address:
            list_search = list(lookup_ip_address.groups())
            ip_address = list_search[0]

        return ip_address
    
    def get_users_sshd_attempt(self, output:str) -> str | None:
        """Retourn le user si disponible

        Args:
            output (str): journalctl output

        Returns:
            str | None: if available user
        """
        user = None
        patterns = [
            r'.*user=(\w*)',
            r'^.*Invalid user\s(\D*?)\s.*$',
            r'^.*Failed password for invalid user (\D*?)\s.*$',
            r'^.*Failed password for (\D*?)\s.*$'
        ]

        for pattern in patterns:
            lookup_user = re.search(pattern, output)
            if lookup_user:
                list_search = list(lookup_user.groups())
                user = list_search[0]
        
        return user