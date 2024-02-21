import json, os
from core import base

class Parser:

    def __init__(self, base:base.Base) -> None:

        self.Base = base        
        self.all_modules:dict = {}

        self.process:list = []              # List of processes ()
        self.filenames:list = []            # Liste contenant le nom des fichiers

        self.load_json_configuration()
        self.parse_json()

        return None

    def load_all_modules(self, json_data:dict) -> None:

        self.all_modules[json_data['process']] = json_data

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
                    # print(f'== File "{file}" has been loaded')
                    self.load_all_modules(json_data)

                no_files += 1

        return no_files

    def parse_json(self) -> None:

        # Charger le nombre de process existants
        for key, values in self.all_modules.items():
            self.process.append(key)
        
        return None
        ## get process
        for key, values  in self.json_conf.items():
            
            # Inserer les informations de base
            if type(values) == str:
                match key:
                    case 'process':
                        self.process.append(self.json_conf[key])
                    case 'rgx_process_name':
                        self.rgx_process_name.append(self.json_conf[key])
                    case 'rgx_process_id':
                        self.rgx_process_id.append(self.json_conf[key])

            # Insérer les filtres
            if type(values) == dict:
                for k, v in values.items():
                    self.filters.append(v)

        return None