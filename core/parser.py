import json, os
from core import base

class Parser:

    def __init__(self, base:base.Base) -> None:

        self.Base = base                                # The Instance of the Base object
        self.modules:dict[any, dict] = {}               # Charger l'ensemble des modules
        self.global_configuration:dict[any, dict] = {}  # Global configuration
        self.global_ip_exceptions:list = []             # Global ip exceptions

        self.global_api:dict[any, dict] = {}            # Global API for ip checks
        
        self.module_names:list = []                     # List of module names () ==> ["sshd","dovecot","proftpd"]
        self.filenames:list = []                        # Liste contenant le nom des fichiers de configuration json
        self.errors:list = []                           # check errors
        
        self.load_global_json_configuration()
        self.load_json_configuration()
        self.parse_json()

        self.intercept_initialization()
        #Cron(self.Base, 'Parser').init()                          # Lancer le cron

        if self.errors:
            for error in self.errors:
                self.Base.log_print(error,'red')

        return None

    def load_global_json_configuration(self) -> None:
        """Load global configuration file
        """
        
        filename = f'core{os.sep}global.json'

        with open(filename, 'r') as globalfile:
            self.global_configuration:dict[any, dict] = json.load(globalfile)

        for key, value in self.global_configuration.items():

            for key_exception, value_ip_exceptions in value.items():
                if type(value_ip_exceptions) == list and key_exception == 'ip_exceptions':
                    for global_ip_exception in value_ip_exceptions:
                        self.global_ip_exceptions.append(global_ip_exception)
                if type(value_ip_exceptions) == dict and key_exception == 'abuseipdb':
                    self.global_api[key_exception] = value_ip_exceptions
                    
                    if 'jail_score' in self.global_api[key_exception]:
                        self.Base.abuseipdb_jail_score = self.global_api[key_exception]['jail_score']
                    if 'jail_duration' in self.global_api[key_exception]:
                        self.Base.abuseipdb_jail_duration = self.global_api[key_exception]['jail_duration']

        return None

    def load_json_configuration(self) -> int:
        """Load files and return number of loaded files

        Returns:
            int: Number of configuration files loaded
        """
        path = f'modules{os.sep}'
        no_files = 0

        list_files_in_directory = os.listdir(path)

        for file in list_files_in_directory:
            if file.endswith('.json'):
                self.filenames.append(file)                     # Enregistrer le nom des fichiers
                with open(f'{path}{file}', 'r') as f:
                    json_data = json.load(f)
                    if self.check_json_structure(json_data, file):
                        self.load_modules(json_data)
                        no_files += 1
                    else:
                        self.filenames.remove(file)


        return no_files

    def load_modules(self, json_data:dict) -> None:

        try:
            self.modules[json_data['module_name']] = json_data

            return None
        except KeyError as ke:
            self.Base.log_print(f'"{self.load_modules.__name__}" Key Error detected - {ke}','red')

    def parse_json(self) -> None:
        
        # Charger le nom des modules existants
        for module_name in self.modules:
            self.module_names.append(module_name)
        
        return None

    def check_json_structure(self, json_data:dict, filename:str) -> bool:
        
        response = True
        mandatory_keys = ['module_name','rgx_service_name','rgx_service_id','filters','actions']

        for mandator_key in mandatory_keys:
            if not mandator_key in json_data:
                self.errors.append(f'Key : {mandator_key} missing in {filename}')
                response = False


        return response

    def intercept_initialization(self) -> None:

        message = '#            Starting Interceptor Security    '
        hn  = f'#    Hostname               : {self.Base.HOSTNAME}\n'
        hn += f'#    IPV4                   : {self.Base.IPV4}\n'
        hn += f'#    Interceptor Version    : {self.Base.VERSION}\n'
        hn += f'#    Python Version         : {self.Base.CURRENT_PYTHON_VERSION}\n'
        hn += f'#    Modules loaded         :\n'
        
        for file in self.filenames:
            hn += f'#                            - {file}\n'
        
        taille = len(message) + 5

        print('#' * taille)
        print(message)
        print(hn)
        print('#' * taille)

        return None
