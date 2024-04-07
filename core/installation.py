from importlib.util import find_spec
from subprocess import check_call
from platform import python_version
from sys import exit
import os

class Install:

    def __init__(self) -> None:

        self.PYTHON_MIN_VERSION = '3.9'
        self.module_to_install = ['sqlalchemy','requests']
        self.updating_pip = False

        if not self.checkPythonVersion():
            # Tester si c'est la bonne version de python
            exit("Python Version Error")
        else:
            # Sinon tester les dependances python et les installer avec pip
            self.checkDependencies()

        self.generate_json_configuration()
        return None

    def checkPythonVersion(self) -> bool:
        """Test si la version de python est autorisée ou non

        Returns:
            bool: True si la version de python est autorisé sinon False
        """
        python_required_version = self.PYTHON_MIN_VERSION.split('.')
        python_current_version = python_version().split('.')

        if int(python_current_version[0]) < int(python_required_version[0]):
            print(f"## Your python version must be greather than or equal to {self.PYTHON_MIN_VERSION} ##")
            return False
        elif int(python_current_version[1]) < int(python_required_version[1]):
            print(f"### Your python version must be greather than or equal to {self.PYTHON_MIN_VERSION} ###")
            return False

        return True

    def checkDependencies(self) -> None:
        """### Verifie les dépendances si elles sont installées
        - Test si les modules sont installés
        - Met a jour pip
        - Install les modules manquants
        """
        do_install = False

        for module in self.module_to_install:
            if find_spec(module) is None:
                do_install = True

        if not do_install:
            return None

        if self.updating_pip:
            print("===> Removing pip cache")
            check_call(['pip','cache','purge'])

            print("===> Check if pip is up to date")
            check_call(['python', '-m', 'pip', 'install', '--upgrade', 'pip'])

        if find_spec('greenlet') is None:
            check_call(['pip','install', '--only-binary', ':all:', 'greenlet'])
            print('====> Module Greenlet installed')

        for module in self.module_to_install:
            if find_spec(module) is None:
                print("### Trying to install missing python packages ###")
                check_call(['pip','install', module])
                print(f"====> Module {module} installed")
            else:
                print(f"==> {module} already installed")

    def generate_json_configuration(self) -> None:

        modules_folder  = f'modules{os.sep}'

        dovecot_file    = 'dovecot.json'
        proftpd_file    = 'proftpd.json'
        sshd_file       = 'sshd.json'

        global_json_file     = f'core{os.sep}global.json'

        dovecot_json = '''{
    "module_name": "dovecot",
    "rgx_service_name": "^.*(dovecot).*$",
    "rgx_service_id": "^.*dovecot\\\[(\\\d*)\\\].*$",
    "inc_service_id": true,
    "rgx_username": "^.*user=<(\\\w+)>.*$",

    "filters": {
        "auth_failure": "^.*(auth failed).*$"
    },

    "filters_ip": {
        "rip": "^.*rip=(\\\d{1,3}\\\.\\\d{1,3}\\\.\\\d{1,3}\\\.\\\d{1,3}).*$"
    },

    "ip_exceptions": ["192.168.1.11","192.168.1.12"],

    "actions": {
        "attempt": 4,
        "jail_duration": 50
    }
}'''

        proftpd_json = '''{
    "module_name": "proftpd",
    "source_log": "/var/log/proftpd/proftpd.log",
    "rgx_service_name": "(proftpd\\\[\\\d*\\\])",
    "rgx_service_id": "^.*proftpd\\\[(\\\d*)\\\].*$",
    "rgx_username": "^.*USER\\\s+(\\\w+)\\\\b.*$",

    "filters": {
        "incorrect_password": "^.*(Incorrect password)$",
        "invalid_user": "^.*(no such user found from).*$"
    },

    "ip_exceptions": ["192.168.1.11","192.168.1.12"],

    "actions": {
        "attempt": 4,
        "jail_duration": 50
    }
}
'''

        sshd_json = '''{
    "module_name": "sshd",
    "rgx_service_name": "(sshd\\\[\\\d*\\\])",
    "rgx_service_id": "^.*sshd\\\[(\\\d*)\\\].*$",

    "filters": {
        "auth_failure": "^.*(authentication failure).*$",
        "invalid_user": "^.*(Invalid user).*$",
        "failed_password": "^.*(Failed password).*$",
        "negociation_failed": ".*(Unable to negotiate).*(no matching key exchange method found).*$"
    },

    "ip_exceptions": ["192.168.1.11","192.168.1.12"],

    "actions": {
        "attempt": 4,
        "jail_duration": 50
    }
}'''

        global_json = '''{
    "exceptions": {
        "ip_exceptions": ["192.168.1.11","192.168.1.12","127.0.1.1","127.0.0.1"]
    },
    "api": {
        "intc_hq": {
            "active": true,
            "report": true,
            "url": "https://api.deb.biz.st/api/v1/",
            "api_key": "psOSoVA7DJmk5aCLYYVGIEp0VcSj3RRUpJoBGbVfxSPuS8EW9HVZBEIYVWgVdzOE",
            "abuseipdb_jail_score": 95,
            "intc_hq_jail_totalReports": 10,
            "jail_duration": 600
        }
    }
}
'''

        # Create Global.json file if not available
        if not os.path.exists(f'{global_json_file}'):
            with open(f"{global_json_file}", mode="x") as file:
                file.write(global_json)

        # Create modules folder if not available
        if not os.path.exists(modules_folder):
            os.mkdir(modules_folder)

        # Create dovecot file if not available
        if not os.path.exists(f'{modules_folder}{dovecot_file}'):
            with open(f"{modules_folder}{dovecot_file}", mode="x") as file:
                file.write(dovecot_json)

        # Create Proftpd file if not available
        if not os.path.exists(f'{modules_folder}{proftpd_file}'):
            with open(f"{modules_folder}{proftpd_file}", mode="x") as file:
                file.write(proftpd_json)

        # Create sshd file if not available
        if not os.path.exists(f'{modules_folder}{sshd_file}'):
            with open(f"{modules_folder}{sshd_file}", mode="x") as file:
                file.write(sshd_json)

