# Interceptor Security system
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

    - Python 3.10 or higher with SQLAlchemy installed ( pip3 install sqlalchemy )
    - Journalctl (for log file parsing)
    - iptables (for banning and releasing IP addresses)

Installation:

    - python3 -m venv .intenv
    - source ./intenv/bin/activate
    - python main.py
    once the installation and the application is running, i would recommand to create a service and run the application as root.

Contributions:
Contributions, bug reports, and feature requests are welcome. Please feel free to fork the repository, make improvements, and submit pull requests.

License:
This project is licensed under the MIT license. See the LICENSE file for details.

Author:
adator

Contact:
For inquiries or assistance, please contact debian@deb.biz.st.
