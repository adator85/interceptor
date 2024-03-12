import re
from core import base, parser
from subprocess import Popen
from typing import Union

class Intercept:

    __PATTERN_IPV4 = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*$'
    __PATTERN_IPV6 = r'([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})'

    def __init__(self, base: base.Base, parser: parser.Parser, subprocess:Popen, subprocess_detail:dict) -> None:
        
        self.Base                       = base                              # Création d'une instance Base()
        self.Parser                     = parser                            # Création d'une instance Parser()
        self.subprocess                 = subprocess                        # Get the source of the log
        self.subprocess_detail          = subprocess_detail
        self.global_sys_attempt         = self.Base.default_attempt         # Number of attempt for the jail
        self.global_sys_jail_duration   = self.Base.default_jail_duration   # Duration in seconds before the release
        self.default_ip                 = self.Base.default_ipv4            # Default ipv4 to be used by Interceptor

        self.Base.clean_iptables()                                          # Premiere initialisation vider les ban dans la base de données

        return None

    def run_process(self, output:str) -> None:

        for mod_name in self.Parser.module_names:
            if self.subprocess_detail[mod_name] == self.subprocess:
                service = re.search(self.Parser.modules[mod_name]['rgx_service_name'], output)

                if service:
                    self.record_entry(output, mod_name)

        return None
    
    def record_entry(self, output:str, mod_name:str) -> None:

        ip = ''
        ip_exceptions:list = []
        ipv4_address = self.get_ipv4_address(output, mod_name)
        ipv6_address = self.get_ipv6_address(output, mod_name)
        if not ipv4_address is None:
            ip = ipv4_address
        elif not ipv6_address is None:
            ip = ipv6_address
        else:
            ip = self.default_ip

        user = self.get_users_attempt(output, mod_name)
        service_id = self.get_service_id(output, mod_name)
        modules:dict[any, dict] = self.Parser.modules

        # Charger les exceptions du process en cours
        for key, exception in modules[mod_name].items():
            if type(exception) == list and key == 'exceptions':
                for ip_exception in exception:
                    ip_exceptions.append(ip_exception)

        # Charger les filtres du process en cours
        for key, filters in modules[mod_name].items():
            if self.subprocess_detail[mod_name] == self.subprocess:
                if type(filters) == dict and key == 'filters':
                    for filter_name, filter_value in filters.items():
                        lookup = re.search(filter_value, output)
                        if lookup:
                            
                            # Si l'ip est dans liste d'exception globale
                            if ip in self.Parser.global_ip_exceptions:
                                self.Base.log_print(f'Global exception - [{ip}] was exempted from the analysis ...', 'red')

                            # Si l'ip est dans la liste de l'exception du module
                            elif ip in ip_exceptions:
                                self.Base.log_print(f'Module "{mod_name}" exception - [{ip}] was exempted from the analysis ...', 'red')

                            else:
                                # Report to HQ
                                self.Base.report_to_HQ(self.Base.get_sdatetime(), output, ip, service_id)

                                # Get ip information from the HQ
                                self.Base.get_information_from_HQ(ip)

                                if self.Base.db_record_ip(service_id, mod_name, ip, filter_name, user) > 0:
                                    self.Base.log_print(f'{mod_name} - {filter_name} - {service_id} - {ip} - {user} - recorded', 'white')
                                    
                                    local_abuseipdb_information = self.Base.get_local_abuseipdb_score(ip)
                                    if local_abuseipdb_information:
                                        isTor, totalReports, score = self.Base.get_local_abuseipdb_score(ip)
                                        if score >= self.Base.abuseipdb_jail_score:
                                            if self.Base.ip_tables_add(mod_name, ip, self.Base.abuseipdb_jail_duration) > 0:
                                                self.Base.log_print(f'{mod_name} - AbuseIPDB - "{ip}" - Moving to jail for {str(self.Base.abuseipdb_jail_duration)} seconds | Tor: {str(isTor)} / Reports: {str(totalReports)} / Score: {str(score)}', 'red')
                                            self.Base.clean_iptables()
                                        else:
                                            self.execute_action(ip, mod_name)
                                    else:
                                        self.execute_action(ip, mod_name)
       
        return None

    def execute_action(self, received_ip:str, mod_name:str) -> None:
        """Executer un ban au niveau de iptables si les conditions sont réunies

        Returns:
            None: aucun retour requis
        """
        try:
            # for mod_name in self.Parser.module_names:
            if self.subprocess_detail[mod_name] == self.subprocess:
                query = f'''SELECT a.ip as "ip_address", count(DISTINCT(a.service_id)) as "NoAction" 
                            FROM logs as a 
                            WHERE a.module_name = :module_name and a.ip = :ip
                            GROUP BY a.ip
                        '''
                mes_donnees = {'module_name': mod_name, 'ip': received_ip}

                # so far "actions": {'attempt': 4}
                if 'attempt' in self.Parser.modules[mod_name]['actions']:
                    sys_attempt = self.Parser.modules[mod_name]['actions']['attempt']
                else:
                    sys_attempt = self.global_sys_attempt

                if 'jail_duration' in self.Parser.modules[mod_name]['actions']:
                    sys_ban_duration = int(self.Parser.modules[mod_name]['actions']['jail_duration'])
                else:
                    sys_ban_duration = self.global_sys_jail_duration

                cursorResult = self.Base.db_execute_query(query, mes_donnees)
                r = cursorResult.fetchall()

                for results_ip in r:
                    db_ip, db_attempt = results_ip
                    if db_attempt >= sys_attempt:
                        if self.Base.ip_tables_add(mod_name, db_ip, sys_ban_duration) > 0:
                            self.Base.log_print(f'{mod_name} - "{db_ip}" - Moving to jail for {str(sys_ban_duration)} seconds', 'red')
                    
                    self.Base.clean_iptables()

            return None

        except KeyError as ke:
            self.Base.log_print(f'keyError {mod_name} - {__name__} - {self.execute_action.__name__}: key {ke} is not available', 'red')

    def get_service_id(self, output:str, mod_name:str) -> str:
        """Retourn le process id

        Args:
            output (str): journalctl output

        Returns:
            int: process id
        """
        service_id = 0                  # Init process id
        inc_service_id = False          # See if we should inc service id

        if 'inc_service_id' in self.Parser.modules[mod_name]:
            if self.Parser.modules[mod_name]['inc_service_id']:
                unixtime = str(self.Base.get_unixtime())
                inc_service_id = True
            
        #for mod_name in self.Parser.module_names:
        pattern_service_id = self.Parser.modules[mod_name]['rgx_service_id']
        lookup_service_id = re.search(pattern_service_id, output)
        if lookup_service_id:
            list_search = list(lookup_service_id.groups())
            service_id = int(list_search[0])

        if inc_service_id:
            service_id = f'{service_id}_{unixtime}'

        return service_id

    def get_ipv4_address(self, output:str, mod_name:str) -> Union[str, None]:
        """Retourn l'adresse ip si disponible

        Args:
            output (str): journalctl output

        Returns:
            str: ip address (IPV4)
        """
        ip_address = None                  # Init ip address

        if self.subprocess_detail[mod_name] == self.subprocess:
            if 'filters_ip' in self.Parser.modules[mod_name]:
                for key, filter_ip_pattern in self.Parser.modules[mod_name]['filters_ip'].items():
                    lookup_ip = re.search(filter_ip_pattern, output)
                    if lookup_ip:
                        list_search = list(lookup_ip.groups())
                        ip_address = list_search[0]
                        return ip_address
        
        lookup_ip_address = re.search(self.__PATTERN_IPV4, output)
        if lookup_ip_address:
            list_search = list(lookup_ip_address.groups())
            ip_address = list_search[0]

        return ip_address

    def get_ipv6_address(self, output:str, mod_name:str) -> Union[str, None]:
        """Retourn l'adresse ip si disponible

        Args:
            output (str): journalctl output

        Returns:
            str: ip address (IPV6)
        """
        ip_address = None                  # Init ip address
        if self.subprocess_detail[mod_name] == self.subprocess:
            if 'filters_ip' in self.Parser.modules[mod_name]:
                for key, filter_ip_pattern in self.Parser.modules[mod_name]['filters_ip'].items():
                    lookup_ip = re.search(filter_ip_pattern, output)
                    if lookup_ip:
                        list_search = list(lookup_ip.groups())
                        ip_address = list_search[0]
                        return ip_address
        
        lookup_ip_address = re.search(self.__PATTERN_IPV6, output)
        if lookup_ip_address:
            list_search = list(lookup_ip_address.groups())
            ip_address = list_search[0]

        return ip_address

    def get_users_attempt(self, output:str, mod_name:str) -> Union[str, None]:
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
        
        if self.subprocess_detail[mod_name] == self.subprocess:
            if 'rgx_username' in self.Parser.modules[mod_name]:
                pattern = self.Parser.modules[mod_name]['rgx_username']
                lookup_user = re.search(pattern, output)
                if lookup_user:
                    list_search = list(lookup_user.groups())
                    user = list_search[0]
                    return user

        for pattern in patterns:
            lookup_user = re.search(pattern, output)
            if lookup_user:
                list_search = list(lookup_user.groups())
                user = list_search[0]
        
        return user