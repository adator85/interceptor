from importlib.util import find_spec
from subprocess import check_call, CalledProcessError
from platform import python_version
from sys import exit
import os, shutil

# Include all apt requirements
# Include all python requirements
# Include all global variable
#   systemd
#   iptables
#   journalctl
#   tail

class Setup():

    def __init__(self) -> None:
        self.__version__        = '1.1.0'
        self.PYTHON_MIN_VERSION = '3.10'

        if not self.is_root():
            self.iprint('/!\\ user must be root /!\\')
            exit(5)
        
        if not self.checkPythonVersion():
            self.iprint(f'/!\\ You must use correct version of python > {self.PYTHON_MIN_VERSION} /!\\')
            exit(5)

        # Python requirements modules
        self.required_python_modules = ['requests','sqlalchemy']
        
        self.install_folder = os.getcwd()
        self.systemd_folder = f'/etc/systemd/system/'
        self.virtual_env_folder_name = '.intvenv'
        self.venv_full_path = f'{self.install_folder}{os.sep}{self.virtual_env_folder_name}{os.sep}bin{os.sep}python'
        self.interceptor_full_path = f'{self.install_folder}{os.sep}main.py'

      
        self.cmd_venv_command = ['python3', '-m', 'venv', self.virtual_env_folder_name]
        self.cmd_debian_requirements = ['apt', 'install', '-y', 'python3-pip', 'python3-venv', 'iptables']
        
        self.cmd_python_requirements = [f'{self.install_folder}{os.sep}{self.virtual_env_folder_name}{os.sep}bin{os.sep}pip', 'install']
        self.cmd_python_requirements.extend(self.required_python_modules)

        self.cmd_daemon_reload = ['systemctl','daemon-reload']
        self.cmd_start_service = ['systemctl','start','Interceptor']
        self.cmd_status_service = ['systemctl','status','Interceptor']

        self.run_subprocess(self.cmd_debian_requirements)

        self.run_subprocess(self.cmd_venv_command)
        if self.is_python_module_missing(self.required_python_modules):
            self.run_subprocess(self.cmd_python_requirements)

        self.create_service_file()
        self.run_subprocess(self.cmd_daemon_reload)
        self.run_subprocess(self.cmd_start_service)
        self.run_subprocess(self.cmd_status_service)

        return None

    def is_root(self) -> bool:

        if os.geteuid() == 0:
            return True
        else:
            return False

    def is_python_module_missing(self, modules:list) -> bool:

        is_missing = False

        for module in modules:
            if find_spec(module) is None:
                is_missing = True

        return is_missing

    def run_subprocess(self, command:list) -> None:

        self.iprint(command)
        try:            
            check_call(command)
            self.iprint("La commande s'est terminée avec succès.")
        except CalledProcessError as e:
            self.iprint(f"La commande a échoué avec le code de retour :{e.returncode}")
            self.iprint(f"Try to install dependencies ...")
            exit(5)

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

    def iprint(self, messsage:str) -> None:

        print(messsage)

        return None

    def create_service_file(self) -> None:
        
        if os.path.exists(f'{self.systemd_folder}{os.sep}Interceptor.service'):
            self.iprint(f'/!\\ Service already created in the system /!\\')
            return None

        contain = f'''[Unit]
Description=Interceptor Intrusion System (IIS)

[Service]
User=root
ExecStart={self.venv_full_path} {self.interceptor_full_path}
WorkingDirectory={self.install_folder}
SyslogIdentifier=Interceptor
Restart=on-failure

[Install]
WantedBy=multi-user.target
'''
        with open('Interceptor.service.generated', 'w+') as servicefile:
            servicefile.write(contain)
            servicefile.close()
            self.iprint(f'Service file generated with current configuration')

            source = f'{self.install_folder}{os.sep}Interceptor.service.generated'
            destination = f'{self.systemd_folder}'
            shutil.copy(source, destination)
            os.rename(f'{self.systemd_folder}{os.sep}Interceptor.service.generated', f'{self.systemd_folder}{os.sep}Interceptor.service')
            self.iprint(f'Service file moved to systemd folder {self.systemd_folder}')
        
Setup()