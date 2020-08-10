# RedShell
An interactive command prompt that executes commands through proxychains and automatically logs them on a Cobalt Strike team server.

# Installation
RedShell runs on Python 3. It also requires a Cobalt Strike client installed on the system where it runs.

Install dependencies:
```
pip3 install -r requirements.txt
```
Install proxychains-ng (https://github.com/rofl0r/proxychains-ng):
```
apt install proxychains4
```
Make the agscript wrapper executable:
```
chmod +x agscript.sh
```

# Usage
Start a socks listener on a beacon in your Cobalt Strike client.

Edit your proxychains config with the beacon socks port.

Start RedShell:
```
$ python3 redshell.py 

                ____           _______ __         ____
               / __ \___  ____/ / ___// /_  ___  / / /
              / /_/ / _ \/ __  /\__ \/ __ \/ _ \/ / / 
             / _, _/  __/ /_/ /___/ / / / /  __/ / /  
            /_/ |_|\___/\__,_//____/_/ /_/\___/_/_/

            
RedShell> 

```

Display help:
```
RedShell> help

Documented commands (use 'help -v' for verbose/'help <topic>' for details):
===========================================================================
beacon_exec  connect     help         pwd   shell        use_pivot
cd           disconnect  history      quit  show_pivots
config       exit        load_config  set   status 
```

Set options:
```
RedShell> set option VALUE
```

## Connecting to Cobalt Strike

Set Cobalt Strike connection options:
```
RedShell> set cs_host 127.0.0.1
RedShell> set cs_port 50050
RedShell> set cs_user somedude
```

Connect to team server (you will be prompted for the team server password):
```
RedShell> connect 
Enter Cobalt Strike password:
Connecting...
╔═══════════════════════╤═══════════════════════════════════════════════════════╗
║ CS team server status │ Connected via somedude_redshell@127.0.0.1:50050       ║
╟───────────────────────┼───────────────────────────────────────────────────────╢
║ Socks port status     │ Disconnected                                          ║
╚═══════════════════════╧═══════════════════════════════════════════════════════╝

```

Or load from a config file. Note: team server passwords are not read from config files. Redshell will prompt for the teamserver password and then automatically connect.
```
$ cat config.txt 
cs_host=127.0.0.1
cs_port=12345
cs_user=somedude
```
```
RedShell> load_config config.txt
Config applied:              
╔════════════════════════════╤═══════════════════════════════════════════════════════╗
║ Redshell install directory │ /opt/redshell                                         ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Proxychains config         │ /opt/redshell/proxychains_redshell.conf               ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS install directory       │ /opt/cobaltstrike                                     ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS team server             │ 127.0.0.1                                             ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS team server port        │ 50050                                                 ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS user                    │ somedude_redshell                                     ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Socks port                 │                                                       ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Beacon PID                 │                                                       ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Password                   │                                                       ║
╚════════════════════════════╧═══════════════════════════════════════════════════════╝

Enter Cobalt Strike password: 

╔═══════════════════════╤═══════════════════════════════════════════════════════╗
║ CS team server status │ Connected via somedude_redshell@127.0.0.1:50050       ║
╟───────────────────────┼───────────────────────────────────────────────────────╢
║ Socks port status     │ Disconnected                                          ║
╚═══════════════════════╧═══════════════════════════════════════════════════════╝
```

Show available proxy pivots:
```
RedShell> show_pivots 
╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ ID     Alive   Socks Port    PID         User                       Computer                   Last         ║
╠═════════════════════════════════════════════════════════════════════════════════════════════════════════════╣
║ 1      True    22200         8948        Administrator *            WS02                       16ms         ║
╟─────────────────────────────────────────────────────────────────────────────────────────────────────────────╢
║ 2      True    54212         7224        Administrator *            WS03                       39ms         ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝

```

Select a proxy pivot (note: this can only be set after a connection to the team server has been established):
```
RedShell> use_pivot 2

╔═══════════════════════╤════════════════════════════════════════════════════════════╗
║ CS team server status │ Connected via somedude_redshell@127.0.0.1:50050            ║
╟───────────────────────┼────────────────────────────────────────────────────────────╢
║ Socks port status     │ Connected via socks port 54212 @ beacon PID 7224           ║
╚═══════════════════════╧════════════════════════════════════════════════════════════╝
```

Check config
```
RedShell> config 

╔════════════════════════════╤═══════════════════════════════════════════════════════╗
║ Redshell install directory │ /opt/redshell                                         ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Proxychains config         │ /opt/redshell/proxychains_redshell.conf               ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS install directory       │ /opt/cobaltstrike                                     ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS team server             │ 127.0.0.1                                             ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS team server port        │ 50050                                                 ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ CS user                    │ somedude_redshell                                     ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Socks port                 │                                                       ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Beacon PID                 │                                                       ║
╟────────────────────────────┼───────────────────────────────────────────────────────╢
║ Password                   │                                                       ║
╚════════════════════════════╧═══════════════════════════════════════════════════════╝
```

Check status:
```
RedShell> status

╔═══════════════════════╤════════════════════════════════════════════════════════════╗
║ CS team server status │ Connected via somedude_redshell@127.0.0.1:50050            ║
╟───────────────────────┼────────────────────────────────────────────────────────────╢
║ Socks port status     │ Connected via socks port 54212 @ beacon PID 7224           ║
╚═══════════════════════╧════════════════════════════════════════════════════════════╝
        
```

Execute commands through the beacon socks proxy. These can be run in the context of the current user or via sudo. Specifying 'proxychains' in the command is optional. Commands are forced through proxychains. MITRE ATT&CK Tactic IDs are optional. Including
```
RedShell> beacon_exec -h
usage: beacon_exec [-h] [-t TTP] ...

Execute a command through proxychains/beacon socks proxy and simultaneously log it to the teamserver.

positional arguments:
  command            Command to execute through the proxy.

optional arguments:
  -h, --help         show this help message and exit
  -t TTP, --ttp TTP  MITRE ATT&CK Tactic IDs. Comma delimited to specify multiple.

example:
beacon_exec -t T1003,T1075 cme smb --local-auth -u Administrator -H C713B1D611657D0687A568122193F230 --sam 192.168.1.1
```
```
RedShell> beacon_exec cme smb 192.168.1.14
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.14
[proxychains] Strict chain  ...  127.0.0.1:48199  ...  192.168.1.14:445  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:48199  ...  192.168.1.14:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:48199  ...  192.168.1.14:445  ...  OK
SMB         192.168.1.14    445    TESTNET-DC1      [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:TESTNET-DC1) (domain:TESTNET) (signing:True) (SMBv1:True)

```
Note on passwords used in beacon_exec commands - special characters in passwords may be interpreted as shell meta characters, which could cause commands to fail. To get around this, set the password option and then invoke with '$password'. Example:
```
RedShell> set password Test12345
password - was: ''
now: 'Test12345'
RedShell> beacon_exec cme smb --local-auth -u administrator -p $password --shares 192.168.1.14
```

Note on the Redshell and CS install directory options - the script needs to know where it lives, as well as Cobalt Strike.
If stuff blows up, be sure to set the directories accordingly:
```
RedShell> set redshell_directory /opt/redshell
RedShell> set cs_directory /opt/cobaltstrike
```

## General Features

RedShell includes commands for navigating the file system:
```
RedShell> cd /opt/redshell/
RedShell> pwd
/opt/redshell
```

Additional commands can be run via the shell command or via the '!' shortcut:
```
RedShell> shell date
Mon 29 Jul 2019 05:33:02 PM MDT
RedShell> !date
Mon 29 Jul 2019 05:33:03 PM MDT
```

Commands are tracked and accessible via the history command:
```
RedShell> history 
    1  load_config config.txt
    2  status
    3  help
```

RedShell also includes tab-completion and clearing the terminal window via ctrl + l.

## Maintainers

 - [exfiltrata](https://github.com/exfiltrata)

## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to [LICENSE](LICENSE.md) for the full terms.