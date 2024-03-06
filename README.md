# Interceptor Intrusion Detector system
Description:

    Interceptor is a Python application designed to scan log files from the Journalctl and identify potential attacks.
    It operates by parsing log files for suspicious patterns, which are configurable via JSON rule sets.
    Upon detecting an attack, Interceptor logs the event and bans the source IP address using iptables firewall rules.
    Additionally, the application provides functionality to release the banned IP addresses after a configurable time period.

Key Features:

    Log File Scanner: Parses log files from Journalctl to identify potential attacks.
    Rule-Based Detection: Utilizes JSON rule sets to configure patterns for detecting attacks.
    Attack Logging: Logs detected attacks along with relevant information for analysis.
    IP Address Ban: Bans detected attacker IP addresses using iptables firewall rules.
    Configurable Release Time: Allows specifying a time interval for releasing banned IP addresses.
    GitHub Repository: Provides the application's source code and documentation for easy access and collaboration.

Usage:

    Configure the JSON rule sets according to the desired attack patterns.
    Run the application to scan log files and detect attacks.
    Detected attacks are logged, and corresponding IP addresses are banned using iptables.
    Banned IP addresses are automatically released after the specified time interval.
    Note: It's important to ensure proper permissions and access rights for the application to read log files and interact with iptables.

GitHub Repository: https://github.com/adator85/Interceptor

Requirements:

    - Python3-venv and Python3-pip
    - Python >=3.9 with following libraries:
            - requests
            - sqlalchemy
    - Journalctl (for log file parsing)
    - iptables (for banning and releasing IP addresses)

Installation:

    - Automatic installation (root):
        sudo su
        git clone https://github.com/adator85/Interceptor.git ~/Interceptor && cd ~/Interceptor && python3 ~/Interceptor/install.py
        
        if you want to see the logs in real time :
        tail -f ~/Interceptor/logs/intercept.log
    
    - Manual installation (root):
        cd ~
        git clone https://github.com/adator85/Interceptor.git
        cd Interceptor        
        apt install -y python3-venv python3-pip iptables
        python3 -m venv .intvenv
        source .intvenv/bin/activate
        python main.py
    
        once the installation and the application is running, i would recommand to create a service and run the application as root with systemctl.

Contributions:

    Contributions, bug reports, and feature requests are welcome. Please feel free to fork the repository, make improvements, and submit pull requests.

License:

    This project is licensed under the MIT license. See the LICENSE file for details.

Contact:

    Author : adator
    contact : debian@deb.biz.st
    IRC Discussion : 
        Connexion server : irc.deb.biz.st
        Port             : 6697 ( for ssl )
                         : 6667
        Channel          : #Interceptor

