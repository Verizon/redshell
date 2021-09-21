# Copyright Verizon.
# Licensed under the terms of the Apache 2.0 license. See LICENSE file in project root for terms.

#!/bin/env python3

import argparse
import csv
import fileinput
import getpass
import os
import re
import shlex
import shutil
import sys
import textwrap
from datetime import datetime, timezone

import pexpect
from cmd2 import Cmd, Settable, with_argparser
from rich import box
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table


def xstr(s):
    """return empty string if input is none/false"""
    
    return '' if not s else s


class Logger():

    logs = []
    logfile_csv = None
    csv_writer = None

    def __init__(self, command, ip=None, dns_name=None, netbios_name=None, user_name=None, pid=None, ttps=None):
        self.timestamp = datetime.now(timezone.utc)
        self.command = command
        self.ip = ip
        self.dns_name = dns_name
        self.netbios_name = netbios_name
        self.user_name = user_name
        self.pid = pid
        self.ttps = ttps
        self.write_log_entry()
        Logger.logs.append(self)


    @classmethod
    def open_logfile(cls, basefilename):

        logfile_csv = f"{basefilename}.csv"
        print("Logging to: ", logfile_csv)
        cls.logfile_csv = open(logfile_csv, 'w', newline='')

        fieldnames = ['Datetime', 'IP Address', 'DNS Name', 'NetBIOS Name', 'User', 'PID', 'Activity', 'TTPs']

        cls.csv_writer = csv.DictWriter(cls.logfile_csv, fieldnames=fieldnames)
        cls.csv_writer.writeheader()
        cls.logfile_csv.flush()

    def asdict(self):

        return {'Datetime': self.timestamp.strftime("%Y/%m/%d %H:%M:%S %z"), 
                'IP Address': xstr(self.ip), 
                'DNS Name': xstr(self.dns_name), 
                'NetBIOS Name': xstr(self.netbios_name), 
                'User': xstr(self.user_name), 
                'PID': xstr(self.pid), 
                'Activity': self.command,
                'TTPs': self.ttps}

    def write_log_entry(self):

        Logger.csv_writer.writerow(self.asdict())
        Logger.logfile_csv.flush()

    @classmethod
    def close_logfile(cls):

        cls.logfile_csv.close()


class CSProxyPivots():

    instances = {}
    count = 0

    def __init__(self, bid, pid, port, user, computer, ip, alive, last):
        self.bid = bid
        self.pid = pid
        self.port = port
        self.user = user
        self.computer = computer
        self.ip = ip
        self.alive = alive
        self.last = last

        CSProxyPivots.count += 1

        self.id = CSProxyPivots.count
        CSProxyPivots.instances[CSProxyPivots.count] = self

    @classmethod
    def get_pivots(cls):

        data = []

        data.append(['ID', 'Alive', 'Socks Port', 'PID', 'User', 'Computer', 'Last'])

        for pivot in CSProxyPivots.instances.values():
            data.append([str(pivot.id), str(pivot.alive), pivot.port, pivot.pid, pivot.user, pivot.computer, pivot.last])

        return data

    @classmethod
    def reset(cls):

        CSProxyPivots.instances.clear()
        CSProxyPivots.count = 0


class RedShell(Cmd):

    intro = """
                ____           _______ __         ____
               / __ \___  ____/ / ___// /_  ___  / / /
              / /_/ / _ \/ __  /\__ \/ __ \/ _ \/ / / 
             / _, _/  __/ /_/ /___/ / / / /  __/ / /  
            /_/ |_|\___/\__,_//____/_/ /_/\___/_/_/

            """

    prompt = 'RedShell> '

    def __init__(self):
        super().__init__()

        # remove built-in commands
        try:
            del Cmd.do_alias
            del Cmd.do_edit
            del Cmd.do_macro
            del Cmd.do_run_pyscript
            del Cmd.do_run_script
            del Cmd.do_shortcuts
            del Cmd.do_py
        except AttributeError:
            pass

        # remove built-in settings
        for key in ['allow_style', 'always_show_hint', 'editor', 'echo', 'feedback_to_output', 'quiet', 'timing', 'max_completion_items']:
            try:
                self.remove_settable(key)
            except:
                pass

        # check/create redshell user dir
        home_dir = os.path.expanduser("~")
        self.redshell_user_directory = f"{home_dir}/.redshell/"
        
        if not os.path.exists(self.redshell_user_directory):
            os.makedirs(self.redshell_user_directory)

        # set cobalt strike directory, if exists
        if os.path.exists('/opt/cobaltstrike'):
            self.cs_directory = '/opt/cobaltstrike'
        else:
            self.cs_directory = ''

        # set config variables
        self.redshell_directory = os.getcwd()
        self.proxychains_config = f"{self.redshell_directory}/proxychains_redshell.conf"
        self.cs_host = ''
        self.cs_port = ''
        self.cs_user = ''
        self.cs_pass = ''
        self.cs_process = None
        self.cs_beacon_pid = ''
        self.cs_beacon_id = ''
        self.cs_beacon_user = ''
        self.cs_beacon_computer = ''
        self.cs_beacon_ip = ''
        self.context_ip = ''
        self.context_dns_name = ''
        self.context_netbios_name = ''
        self.context_user_name = ''
        self.context_pid = ''
        self.socks_host = ''
        self.socks_port = ''
        self.socks_port_connected = False
        self.password = ''

        # initialze user settable options
        self.add_settable(Settable('redshell_directory', str, 'redshell install directory', self, completer=Cmd.path_complete, onchange_cb=self._onchange_redshell_directory))
        self.add_settable(Settable('proxychains_config', str, 'proxychains config file', self, completer=Cmd.path_complete))
        self.add_settable(Settable('cs_directory', str, 'Cobalt Strike install directory', self, completer=Cmd.path_complete))
        self.add_settable(Settable('cs_host', str, 'Cobalt Strike team server host', self))
        self.add_settable(Settable('cs_port', str, 'Cobalt Strike team server port', self))
        self.add_settable(Settable('cs_user', str, 'Cobalt Strike user', self, onchange_cb=self._onchange_cs_user))
        self.add_settable(Settable('password', str, 'Password for beacon_exec commands. Invoke with $password.', self))
           
        # start logger
        now = datetime.now()
        timestamp = now.strftime("%Y_%m_%d_%H_%M_%S")
        basefilename = f"{self.redshell_user_directory}redshell_{timestamp}"
        Logger.open_logfile(basefilename)


    def _onchange_redshell_directory(self, param_name, old, new):

        self.proxychains_config = f"{self.redshell_directory}/proxychains_redshell.conf"
        
    # append '_redshell' to CS username
    def _onchange_cs_user(self, param_name, old, new):

        self.cs_user += '_redshell'

    def print_table(self, data, header=False):
        """print all tables in console output"""

        if header:
            table = Table(show_lines=True, show_header=header)

        else:
            table = Table(show_lines=True, show_header=header, box=box.SQUARE)

        column_count = range(0, len(data[0]))

        for i in column_count:

            if header:
                table.add_column(data[0][i])

            else:
                table.add_column()

        for row in data:

            if header and data.index(row) == 0:
                continue

            table.add_row(*row)

        console = Console()
        console.print(table)

    def update_proxychains_conf(self, socks_type, ip, socks_port):

        for line in fileinput.input(self.proxychains_config, inplace=True): 
            if line.startswith('socks'): 
                print(f"{socks_type} {ip} {socks_port}", end="\n") 
            else: 
                print(line, end = '')

    def clear_context(self, clear_socks=False, clear_cs=False):

         # clear existing connection
        self.cs_beacon_id = ''
        self.cs_beacon_pid = ''
        self.cs_beacon_user = ''
        self.cs_beacon_computer = ''
        self.cs_beacon_ip = ''
        self.context_ip = ''
        self.context_dns_name = ''
        self.context_netbios_name = ''
        self.context_user_name = ''
        self.context_pid = ''

        # clear socks port if user is applying a new one
        if clear_socks:
            self.socks_port = ''
            self.socks_port_connected = False

        # if connected to cs team server, kill connection
        if clear_cs:
            # close the agscript process
            if self.cs_process:
                self.cs_process.close()
                self.cs_process = None

    argparser = argparse.ArgumentParser()
    argparser.add_argument('-d', '--dnsname', type=str, help="DNS Name")
    argparser.add_argument('-n', '--netbiosname', type=str, help="NetBIOS Name")
    argparser.add_argument('-u', '--username', type=str, help="User Name")
    argparser.add_argument('-p', '--pid', type=str, help="Process ID")
    argparser.add_argument(type=str, dest="ip_address", help="Source IP Address")
    @with_argparser(argparser)
    def do_context(self, args):
        """Set a custom context (Source IP/DNS/NetBIOS/User/PID) for logging"""

        if self.context_ip:
            self.poutput("Context changed!")
            self.pwarning("WARNING: If moving to a new socks port, be sure to update your socks connection accordingly.")
        else:
            self.poutput("New context applied!")

        # if connected to cs team server, kill connection and socks. else clear context values only
        if self.cs_process:
            self.clear_context(clear_socks=True, clear_cs=True)
        else:
            self.clear_context()

        self.context_ip = args.ip_address

        if args.dnsname:
            self.context_dns_name = args.dnsname
        if args.netbiosname:
            self.context_netbios_name = args.netbiosname
        if args.username:
            self.context_user_name = args.username
        if args.pid:
            self.context_pid = args.pid

    argparser = argparse.ArgumentParser()
    argparser.add_argument(type=str, dest="socks_type", choices=['socks4', 'socks5'])
    argparser.add_argument(type=str, dest="ip_address")
    argparser.add_argument(type=str, dest="socks_port")
    @with_argparser(argparser)
    def do_socks(self, args):
        """Use a custom socks4/5 port"""

        # clear any existing context, socks port, and cobalt strike connections
        self.clear_context(clear_socks=True, clear_cs=True)
        
        self.socks_host = args.ip_address
        self.socks_port = args.socks_port
        self.socks_port_connected = True
        self.update_proxychains_conf(args.socks_type, args.ip_address, args.socks_port)
        
        self.poutput("Socks port updated.")
        self.pwarning("WARNING: Be sure to update your context accordingly with the 'context' command.")
                
    def do_cs_connect(self, args):
        """Connect to Cobalt Strike team server"""

        self.clear_context(clear_socks=True)

        # check config directories before attempting connection
        if not os.path.exists(f"{self.redshell_directory}/agscript.sh"):
            self.perror("Error: redshell install directory not found! Set the directory with this command: 'set redshell_directory'")
            return

        if not os.path.exists(f"{self.cs_directory}/agscript"):
            self.perror("Error: Cobalt Strike install directory not found! Set the directory with this command: 'set cs_directory'")
            return

        # check permissions on agscript.sh
        if not shutil.which(f"{self.redshell_directory}/agscript.sh"):
            self.perror("Error: agscript.sh does not appear to be executable! Fix it with this command: 'chmod +x agscript.sh'")
            return

        # prompt user for team server password
        self.cs_pass = getpass.getpass("Enter Cobalt Strike password: ")

        # spawn agscript process
        self.cs_process = pexpect.spawn(f"{self.redshell_directory}/agscript.sh {self.cs_directory} {self.cs_host} {self.cs_port} {self.cs_user} {self.cs_pass}")

        # check if process is alive
        if not self.cs_process.isalive():
            self.perror("Error connecting to CS team server! Check config and try again.")
            return                                                          

        # look for the aggressor prompt
        try:
            self.cs_process.expect('.*aggressor.*> ')
        except:
            self.perror("Error connecting to CS team server! Check config and try again.")
            return
        
        self.poutput("Connecting...")

        # upon successful connection, display status
        self.do_cs_status('')

    def do_cs_disconnect(self, args):
        """Disconnect from CS team server"""
        
        self.clear_context(clear_socks=True, clear_cs=True)
       

    def do_cs_status(self, args):
        """Display CS team server and beacon socks port connection status"""

        if self.cs_process and self.cs_process.isalive():
            cs_server_status = f"[green]Connected via {self.cs_user}@{self.cs_host}:{self.cs_port}[/]"

        else:
            cs_server_status = "[red]Disconnected[/]"

        if self.cs_process and self.cs_process.isalive() and self.socks_port_connected:
            socks_port_status = f"[green]Connected via socks port {self.socks_port} @ beacon PID {self.cs_beacon_pid}[/]"

        else:
            socks_port_status = "[red]Disconnected[/]"

        data = [
            ["[i]CS Team Server Status[/]", cs_server_status],
            ["[i]Socks Port Status[/]", socks_port_status]
        ]

        self.print_table(data)


    def do_config(self, args):
        """Display current config"""

        data = [
            ["[i]Redshell Install Directory[/]", self.redshell_directory],
            ["[i]Proxychains Config[/]", self.proxychains_config],
            ["[i]Log File[/]", Logger.logfile_csv.name],
            ["[i]CS Install Directory[/]", self.cs_directory],
        ]

        if self.cs_host:
            data.append(["[i]CS Team Server[/]", self.cs_host])
            data.append(["[i]CS Team Server Port[/]", self.cs_port])
            data.append(["[i]CS User[/]", self.cs_user])

        if self.socks_port:
            data.append(["[i]Socks Host/Port", f"{self.socks_host}:{self.socks_port}"])
        else:
            data.append(["[i]Socks Host/Port", ''])

        context = ''
        if self.context_ip:
            context += f"[i]IP:[/] {self.context_ip}"
        if self.context_dns_name:
            context += f" [i]DNS:[/] {self.context_dns_name}"
        if self.context_netbios_name:
            context += f" [i]NetBIOS:[/] {self.context_netbios_name}"
        if self.context_user_name:
            context += f" [i]User:[/] {self.context_user_name}"
        if self.context_pid:
            context += f" [i]PID:[/] {self.context_pid}"

        data.append(["[i]Context[/]", context])

        if self.password:
            data.append(["[i]Password[/]", self.password])

        self.print_table(data)

    argparser = argparse.ArgumentParser()
    argparser.add_argument(type=str, dest="file_name", completer=Cmd.path_complete)
    @with_argparser(argparser)
    def do_cs_load_config(self, args):
        """Load Cobalt Strike team server config (host, port, and user) from file"""

        self.clear_context(clear_socks=True)

        try:
            with open(args.file_name, 'r') as cf:
                for line in cf.readlines():

                    cs_host = re.search('cs_host=(.*)', line)
                    if cs_host:
                        self.cs_host = cs_host.group(1)

                    cs_port = re.search('cs_port=(.*)', line)
                    if cs_port:
                        self.cs_port = cs_port.group(1)

                    cs_user = re.search('cs_user=(.*)', line)
                    if cs_user:
                        self.cs_user = cs_user.group(1)
                        self.cs_user += '_redshell'

                self.poutput("Config applied:")
                self.do_config('')
                self.do_cs_connect('')                

        except FileNotFoundError:
            self.perror("Error: config file not found!")


    def do_cs_pivots(self, args):
        """Show Cobalt Strike proxy pivots available on the team server"""

        # check for active connection to the team server
        if not self.cs_process or not self.cs_process.isalive():
            self.perror("Error: not connected to CS team server. Connect first and then select a pivot.")
            self.socks_port = ''
            self.cs_beacon_pid = ''
            self.socks_port_connected = False
            return

        else:
            # clear known pivots each time we run this method
            CSProxyPivots.reset()

            # ask agscript for pivots
            self.cs_process.sendline('x pivots()')
            self.cs_process.expect('.*aggressor.*> ')

            if self.cs_process.after:

                # parse through results, only looking for socks proxy pivots
                for result in re.findall('%\(.*?SOCKS4a Proxy.*?\)', self.cs_process.after.decode()):

                    pivot_port = None
                    pivot_bid = None
                    pivot_pid = None
                    pivot_user = ''
                    pivot_computer = None
                    pivot_alive = None
                    pivot_last = None

                    # get socks port
                    result_port = re.search("port => '([0-9]+)'", result)
                    if result_port:
                        pivot_port = result_port.group(1)

                    # get beacon ID
                    result_bid = re.search("bid => '([0-9]+)'", result)
                    if result_bid:
                        pivot_bid = result_bid.group(1)

                    if pivot_bid:

                        # get full beacon info for beacon ID
                        self.cs_process.sendline(f"x beacon_info({pivot_bid})")
                        self.cs_process.expect('.*aggressor.*> ')

                        if self.cs_process.after:

                            beacon_info = self.cs_process.after.decode()

                            # check if beacon is alive or dead
                            result_alive = re.search("alive => 'true'", beacon_info)
                            if result_alive:
                                pivot_alive = True

                            # get beacon user
                            result_user = re.search("user => '(.*?)'", beacon_info)
                            if result_user:
                                pivot_user = result_user.group(1)

                            # get beacon computer
                            result_computer = re.search("computer => '(.*?)'", beacon_info)
                            if result_computer:
                                pivot_computer = result_computer.group(1)

                            # get beacon ip
                            result_ip = re.search("internal => '(.*?)'", beacon_info)
                            if result_ip:
                                pivot_ip = result_ip.group(1)

                            # get beacon pid
                            result_pid = re.search("pid => '([0-9]+)'", beacon_info)
                            if result_pid:
                                pivot_pid = result_pid.group(1)

                            result_last = re.search("lastf => '(.*?)'", beacon_info)
                            if result_last:
                                pivot_last = result_last.group(1)

                    # intialize ProxyPivot instance if we have all the necessary details
                    if pivot_bid and pivot_port and pivot_pid and pivot_computer:
                        CSProxyPivots(bid=pivot_bid, port=pivot_port, pid=pivot_pid, user=pivot_user, computer=pivot_computer, ip=pivot_ip, alive=pivot_alive, last=pivot_last)

                # display ProxyPivot table
                if CSProxyPivots.instances.items():

                    self.print_table(CSProxyPivots.get_pivots(), header=True)

                else:
                    self.pwarning("No proxy pivots found!")


    def do_cs_use_pivot(self, arg_pivot_id):
        """Set RedShell to use Cobalt Strike pivot ID"""

        self.clear_context(clear_socks=True)

        # convert arg to int
        try:
            pivot_id = int(arg_pivot_id)
        except ValueError:
            self.perror('Invalid pivot ID!')
            return

        # get pivot instance by specified ID
        proxy_pivot = CSProxyPivots.instances.get(pivot_id)

        if proxy_pivot:
            
            if proxy_pivot.alive:

                # set config vars from selected ProxyPiot instance
                self.cs_beacon_id = proxy_pivot.bid
                self.cs_beacon_pid = proxy_pivot.pid
                self.cs_beacon_user = proxy_pivot.user
                self.cs_beacon_computer = proxy_pivot.computer
                self.cs_beacon_ip = proxy_pivot.ip
                self.context_ip = self.cs_beacon_ip
                self.context_netbios_name = self.cs_beacon_computer
                self.context_user_name = self.cs_beacon_user
                self.context_pid = self.cs_beacon_pid
                self.socks_host = self.cs_host
                self.socks_port = proxy_pivot.port
                self.socks_port_connected = True
                self.update_proxychains_conf('socks4', self.cs_host, self.socks_port)

                self.do_cs_status('')
                return

            else:
                self.pwarning('Specified pivot ID is not alive!')
                return

        else:
            self.perror('Invalid pivot ID!')
            return

    def do_cd(self, args):
        """Change directory"""

        os.chdir(args)

    # configure auto complete on the cd command
    complete_cd = Cmd.path_complete

    def do_pwd(self, args):
        """Print working directory"""

        self.poutput(os.getcwd())

    def do_exit(self, args):
        """Exit RedShell"""

        Logger.close_logfile()

        return True

    def validate_ttps(self, ttps):

        ttps_valid = []
                
        ttps_check = ttps.split(',')

        for ttp in ttps_check:
            if re.match('^(T[0-9]{4})(\.[0-9]{3})?$', ttp):
                ttps_valid.append(ttp)
            else:
                self.pwarning(f"Invalid TTP specified: {ttp}. Not including in log.")

        validated_ttps = ', '.join(ttps_valid)

        return validated_ttps

    argparser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    argparser.description = "Execute a command through beacon socks proxy and simultaneously log it to the teamserver."
    argparser.epilog = textwrap.dedent('''

           example: 
           beacon_exec -t T1550.002,T1003.002 cme smb 192.168.1.1 --local-auth -u Administrator -H C713B1D611657D0687A568122193F230 --sam
    ''')

    argparser.add_argument('-t', '--ttp', type=str, help="MITRE ATT&CK Tactic IDs. Comma delimited to specify multiple.")
    argparser.add_argument('command', nargs=argparse.REMAINDER, help="Command to execute through the beacon proxy and log.", completer=Cmd.shell_cmd_complete)
    @with_argparser(argparser)
    def do_beacon_exec(self, args):

        # check if agscript process is alive
        if not self.cs_process or not self.cs_process.isalive():
            self.perror("Error: not connected to CS team server. Connect first and then select a pivot.")
            return

        # check if socks port is connected
        elif not self.socks_port_connected:
            self.perror("Error: socks port not connected!")
            return

        else:
            # make a copy of the user-specified command
            command_list = args.command

            # add proxychains to the command if user didn't include it
            if 'proxychains' not in command_list:
                id = 0
                if 'sudo' in command_list:
                    id = 1
                for item in ['proxychains', '-f', self.proxychains_config]:
                    command_list.insert(id, item)
                    id += 1

            # convert command list into a string
            command = shlex.join(command_list)
            
            if '$password' in command and not self.password:
                self.perror("Error: $password invoked, but password is not set. Add it with command: set password <password>")
                return

            command = re.sub("\$password", self.password, command)

            # only log the command (minus sudo and proxychains)
            cs_log_command = re.sub("proxychains.*?conf |sudo ", '', command)
            cs_log_command = re.sub("\\\\", "\\\\\\\\", cs_log_command)
            cs_log_command = re.sub("\$", "\$", cs_log_command) # escape $ char
            cs_log_command = cs_log_command.replace('"', '\\"') # escape " char
            cs_log_command = f"[PROXY] {cs_log_command}"  # append [PROXY] to logged command

            log_command = re.sub("proxychains.*?conf |sudo ", '', command)
            log_command = f"[PROXY] {log_command}"  # append [PROXY] to logged command

            ttps = ''
            if args.ttp:
                ttps = self.validate_ttps(args.ttp)

            if ttps:
                # log command with TTPs to team server
                self.cs_process.sendline(f'x btask({self.cs_beacon_id}, "{cs_log_command}", "{ttps}")')
                self.cs_process.expect('.*aggressor.*> ')

            else:
                # log command without TTPs to team server
                self.cs_process.sendline(f'x btask({self.cs_beacon_id}, "{cs_log_command}")')
                self.cs_process.expect('.*aggressor.*> ')

            Logger(log_command, ip=self.cs_beacon_ip, netbios_name=self.cs_beacon_computer, user_name=self.cs_beacon_user, pid=self.cs_beacon_pid, ttps=ttps.replace(' ', ''))

            # run the command
            self.do_shell(command)

    argparser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    argparser.description = "Execute a command through custom socks proxy and simultaneously log it to the local file."
    argparser.epilog = textwrap.dedent('''

           example: 
           proxy_exec -t T1550.002,T1003.002 cme smb 192.168.1.1 --local-auth -u Administrator -H C713B1D611657D0687A568122193F230 --sam
    ''')

    argparser.add_argument('-t', '--ttp', type=str, help="MITRE ATT&CK Tactic IDs. Comma delimited to specify multiple.")
    argparser.add_argument('command', nargs=argparse.REMAINDER, help="Command to execute through the proxy and log.", completer=Cmd.shell_cmd_complete)
    @with_argparser(argparser)
    def do_proxy_exec(self, args):
        
        # check if socks port is connected
        if not self.socks_port_connected:
            self.perror("Error: socks port not connected!")
            return

        # make a copy of the user-specified command
        command_list = args.command

        # add proxychains to the command if user didn't include it
        if 'proxychains' not in command_list:
            id = 0
            if 'sudo' in command_list:
                id = 1
            for item in ['proxychains', '-f', self.proxychains_config]:
                command_list.insert(id, item)
                id += 1

        # convert command list into a string
        command = shlex.join(command_list)
        
        if '$password' in command and not self.password:
            self.perror("Error: $password invoked, but password is not set. Add it with command: set password <password>")
            return

        command = re.sub("\$password", self.password, command)

        # only log the command (minus sudo and proxychains)
        log_command = re.sub("proxychains.*?conf |sudo ", '', command)

        # append [PROXY] to logged command
        log_command = f"[PROXY] {log_command}"

        ttps = ''
        if args.ttp:
            ttps = self.validate_ttps(args.ttp)

        Logger(log_command, ip=self.context_ip, dns_name=self.context_dns_name, netbios_name=self.context_netbios_name, user_name=self.context_user_name, pid=self.context_pid, ttps=ttps.replace(' ', ''))

        # run the command
        self.do_shell(command)

    argparser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    argparser.description = "Execute a command and log it to the local file."
    argparser.epilog = textwrap.dedent('''

           example: 
           exec -t T1550.002,T1003.002 cme smb 192.168.1.1 --local-auth -u Administrator -H C713B1D611657D0687A568122193F230 --sam
    ''')

    argparser.add_argument('-t', '--ttp', type=str, help="MITRE ATT&CK Tactic IDs. Comma delimited to specify multiple.")
    argparser.add_argument('command', nargs=argparse.REMAINDER, help="Command to execute and log.", completer=Cmd.shell_cmd_complete)
    @with_argparser(argparser)
    def do_exec(self, args):

        # make a copy of the user-specified command
        command_list = args.command

        # convert command list into a string
        command = shlex.join(command_list)
        
        if '$password' in command and not self.password:
            self.perror("Error: $password invoked, but password is not set. Add it with command: set password <password>")
            return

        command = re.sub("\$password", self.password, command)

        # only log the command (minus sudo)
        log_command = re.sub("sudo ", '', command)

        ttps = ''
        if args.ttp:
            ttps = self.validate_ttps(args.ttp)

        Logger(log_command, ip=self.context_ip, dns_name=self.context_dns_name, netbios_name=self.context_netbios_name, user_name=self.context_user_name, pid=self.context_pid, ttps=ttps.replace(' ', ''))

        # run the command
        self.do_shell(command)


if __name__ == '__main__':

    app = RedShell()
    sys.exit(app.cmdloop())
