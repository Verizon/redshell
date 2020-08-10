# Copyright Verizon.
# Licensed under the terms of the Apache 2.0 license. See LICENSE file in project root for terms.

#!/bin/env python3

from cmd2 import Cmd, Settable, with_argparser, ansi
from cmd2.table_creator import Column, BorderedTable
import sys
import os
import pexpect
import re
import getpass
import argparse
import shutil
import textwrap
import fileinput
import functools
from typing import Any, List


class ProxyPivots():

    instances = {}
    count = 0

    def __init__(self, bid, pid, port, user, computer, alive, last):
        self.bid = bid
        self.pid = pid
        self.port = port
        self.user = user
        self.computer = computer
        self.alive = alive
        self.last = last

        ProxyPivots.count += 1

        self.id = ProxyPivots.count
        ProxyPivots.instances[ProxyPivots.count] = self

    def get_list(self):
        return [self.id, self.alive, self.port, self.pid, self.user, self.computer, self.last]

    @classmethod
    def reset(cls):

        ProxyPivots.instances.clear()
        ProxyPivots.count = 0


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
            del Cmd.do_pyscript  # removed in cmd2 v0.9.15
            del Cmd.do_load  # removed in cmd2 v0.9.15
        except AttributeError:
            pass

        # remove built-in settings
        for key in ['allow_style', 'editor', 'debug', 'echo', 'feedback_to_output', 'quiet', 'timing', 'max_completion_items']:
            try:
                self.remove_settable(key)
            except:
                pass

        # set config variables
        self.redshell_directory = os.getcwd()
        self.proxychains_config = "{}/proxychains_redshell.conf".format(self.redshell_directory)
        self.cs_directory = '/opt/cobaltstrike'
        self.cs_host = ''
        self.cs_port = ''
        self.cs_user = ''
        self.cs_pass = ''
        self.socks_port = ''
        self.beacon_pid = ''
        self.bid = ''
        self.socks_port_connected = False
        self.cs_process = None
        self.password = ''

        # initialze user settable options
        self.add_settable(Settable('redshell_directory', str, 'redshell install directory', completer_method=Cmd.path_complete, onchange_cb=self._onchange_redshell_directory))
        self.add_settable(Settable('proxychains_config', str, 'proxychains config file', completer_method=Cmd.path_complete))
        self.add_settable(Settable('cs_directory', str, 'Cobalt Strike install directory', completer_method=Cmd.path_complete))
        self.add_settable(Settable('cs_host', str, 'Cobalt Strike team server host'))
        self.add_settable(Settable('cs_port', str, 'Cobalt Strike team server port'))
        self.add_settable(Settable('cs_user', str, 'Cobalt Strike user', onchange_cb=self._onchange_cs_user))
        self.add_settable(Settable('password', str, 'Password for beacon_exec commands. Invoke with $password.'))
           
    def _onchange_redshell_directory(self, param_name, old, new):

        self.proxychains_config = "{}/proxychains_redshell.conf".format(self.redshell_directory)
        
    # append '_redshell' to CS username
    def _onchange_cs_user(self, param_name, old, new):

        self.cs_user += '_redshell'

    def update_proxychains_conf(self):

        for line in fileinput.input(self.proxychains_config, inplace=True): 
            if line.startswith('socks4'): 
                print("socks4 {} {}".format(self.cs_host, self.socks_port), end="\n") 
            else: 
                print(line, end = '')
                
    def do_connect(self, args):
        """Connect to CS team server"""

        # check config directories before attempting connection
        if not os.path.exists("{}{}".format(self.redshell_directory, "/agscript.sh")):
            self.perror("Error: redshell install directory not found! Set the directory with this command: 'set redshell_directory'")
            return

        if not os.path.exists("{}{}".format(self.cs_directory, "/agscript")):
            self.perror("Error: Cobalt Strike install directory not found! Set the directory with this command: 'set cs_directory'")
            return

        # check permissions on agscript.sh
        if not shutil.which("{}{}".format(self.redshell_directory, "/agscript.sh")):
            self.perror("Error: agscript.sh does not appear to be executable! Fix it with this command: 'chmod +x agscript.sh'")
            return

        # prompt user for team server password
        self.cs_pass = getpass.getpass("Enter Cobalt Strike password: ")

        # spawn agscript process
        self.cs_process = pexpect.spawn("{}/agscript.sh {} {} {} {} {}".format(self.redshell_directory,
                                                                            self.cs_directory,
                                                                            self.cs_host,
                                                                            self.cs_port,
                                                                            self.cs_user,
                                                                            self.cs_pass))

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
        self.do_status('')

    def do_disconnect(self, args):
        """Disconnect from CS team server"""
        
        # close the agscript process
        if self.cs_process:
            self.cs_process.close()
        
        # clear config vars
        self.socks_port = ''
        self.beacon_pid = ''
        self.bid = ''
        self.socks_port_connected = False

    def print_generic_table(self, data):

        columns: List[Column] = list()
        data_list: List[List[Any]] = list()

        max_len0 = 0
        max_len1 = 0
        for row in data:
            col_len = len(row[0])
            if col_len > max_len0:
                max_len0 = col_len
            col_len = len(row[1])
            if col_len > max_len1:
                max_len1 = col_len
            data_list.append(row)

        columns.append(Column("", width=max_len0))
        columns.append(Column("", width=max_len1))

        bt = BorderedTable(columns)
        table = bt.generate_table(data_list, include_header=False)
        ansi.style_aware_write(sys.stdout, table + '\n\n')
        

    def do_status(self, args):
        """Display CS team server and beacon socks port connection status"""
        
        green = functools.partial(ansi.style, fg=ansi.fg.green)
        red = functools.partial(ansi.style, fg=ansi.fg.red)

        if self.cs_process and self.cs_process.isalive():
            cs_server_status = green("Connected via {}@{}:{}".format(self.cs_user, self.cs_host,
                                                                                    self.cs_port))

        else:
            cs_server_status = red("Disconnected")

        if self.socks_port_connected:
            socks_port_status = green("Connected via socks port {} @ beacon PID {}".format(self.socks_port, self.beacon_pid))

        else:
            socks_port_status = red("Disconnected")

        data = [
            ["CS team server status", cs_server_status],
            ["Socks port status", socks_port_status]
        ]

        self.print_generic_table(data)


    def do_config(self, args):
        """Display current config"""

        data = [
            ["Redshell install directory", self.redshell_directory],
            ["Proxychains config", self.proxychains_config],
            ["CS install directory", self.cs_directory],
            ["CS team server", self.cs_host],
            ["CS team server port", self.cs_port],
            ["CS user", self.cs_user],
            ["Socks port", self.socks_port],
            ["Beacon PID", self.beacon_pid],
            ["Password", self.password]
        ]

        self.print_generic_table(data)

    def do_load_config(self, fname):
        """Load CS team server config (host, port, and user) from file"""

        try:

            with open(fname, 'r') as cf:
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
                self.do_connect('')                

        except FileNotFoundError:
            self.perror("Error: config file not found!")

    # configure auto complete on the load_config command
    complete_load_config = Cmd.path_complete


    def print_pivot_table(self):

        bold = functools.partial(ansi.style, bold=True)

        columns: List[Column] = list()
        columns.append(Column(bold("ID"), width=5))
        columns.append(Column(bold("Alive"), width=6))
        columns.append(Column(bold("Socks Port"), width=12))
        columns.append(Column(bold("PID"), width=10))
        columns.append(Column(bold("User"), width=25))
        columns.append(Column(bold("Computer"), width=25))
        columns.append(Column(bold("Last"), width=12))
        
        data_list: List[List[Any]] = list()

        for pivot in ProxyPivots.instances.values():
            data_list.append(pivot.get_list())

        bt = BorderedTable(columns, column_borders=False)
        table = bt.generate_table(data_list)
        ansi.style_aware_write(sys.stdout, table + '\n\n')


    def do_show_pivots(self, args):
        """Show proxy pivots available on the team server"""

        # check for active connection to the team server
        if not self.cs_process or not self.cs_process.isalive():
            self.perror("Error: not connected to CS team server. Connect first and then select a pivot.")
            self.socks_port = ''
            self.beacon_pid = ''
            self.socks_port_connected = False
            return

        else:

            # clear known pivots each time we run this method
            ProxyPivots.reset()

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
                        self.cs_process.sendline('x beacon_info({})'.format(pivot_bid))
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

                            # get beacon pid
                            result_pid = re.search("pid => '([0-9]+)'", beacon_info)
                            if result_pid:
                                pivot_pid = result_pid.group(1)

                            result_last = re.search("lastf => '(.*?)'", beacon_info)
                            if result_last:
                                pivot_last = result_last.group(1)

                    # intialize ProxyPivot instance if we have all the necessary details
                    if pivot_bid and pivot_port and pivot_pid and pivot_computer:
                        ProxyPivots(bid=pivot_bid, port=pivot_port, pid=pivot_pid, user=pivot_user, computer=pivot_computer, alive=pivot_alive, last=pivot_last)

                # display ProxyPivot table
                if ProxyPivots.instances.items():

                    self.print_pivot_table()

                else:
                    self.pwarning("No proxy pivots found!")


    def do_use_pivot(self, arg_pivot_id):
        """Set RedShell to use pivot ID"""

        # clear existing connection
        self.socks_port = ''
        self.bid = ''
        self.beacon_pid = ''
        self.socks_port_connected = False

        # convert arg to int
        try:
            pivot_id = int(arg_pivot_id)
        except ValueError:
            self.perror('Invalid pivot ID!')
            return

        # get pivot instance by specified ID
        proxy_pivot = ProxyPivots.instances.get(pivot_id)

        if proxy_pivot:
            
            if proxy_pivot.alive:

                # set config vars from selected ProxyPiot instance
                self.socks_port = proxy_pivot.port
                self.bid = proxy_pivot.bid
                self.beacon_pid = proxy_pivot.pid
                self.socks_port_connected = True
                self.update_proxychains_conf()

                self.do_status('')
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
        return True

    argparser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter)
    argparser.description = "Execute a command through proxychains/beacon socks proxy and simultaneously log it to the teamserver."
    argparser.epilog = textwrap.dedent('''

           example:
           beacon_exec -t T1003,T1075 cme smb --local-auth -u Administrator -H C713B1D611657D0687A568122193F230 --sam 192.168.1.1
    ''')

    argparser.add_argument('-t', '--ttp', type=str, help="MITRE ATT&CK Tactic IDs. Comma delimited to specify multiple.")
    argparser.add_argument('command', nargs=argparse.REMAINDER, help="Command to execute through the proxy.")
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

                if 'sudo' in command_list:
                    command_list.insert(1, 'proxychains -f {}'.format(self.proxychains_config))
                else:
                    command_list.insert(0, 'proxychains -f {}'.format(self.proxychains_config))

            # convert command list into a string
            command = ' '.join(args.command)

            
            if '$password' in command and not self.password:
                self.perror("Error: $password invoked, but password is not set. Add it with command: set password <password>")
                return

            command = re.sub("\$password", self.password, command)

            # only log the command (minus sudo and proxychains)
            log_command = re.sub("proxychains.*?conf |sudo ", '', command)
            log_command = re.sub("\\\\", "\\\\\\\\", log_command)
            log_command = "[PROXY] {}".format(log_command)

            ttps = None
            if args.ttp:

                ttps_valid = []
                
                ttps_check = args.ttp.split(',')

                for ttp in ttps_check:
                    if re.match('^T[0-9]+$', ttp):
                        ttps_valid.append(ttp)
                    else:
                        self.pwarning('Invalid TTP specified: {}. Not including in log.'.format(ttp))
                
                if ttps_valid:
                    ttps = ', '.join(ttps_valid)

            if ttps:

                # log command with TTPs to team server
                self.cs_process.sendline('x btask({}, "{}", "{}")'.format(self.bid, log_command, ttps))
                self.cs_process.expect('.*aggressor.*> ')

            else:
                # log command without TTPs to team server
                self.cs_process.sendline('x btask({}, "{}")'.format(self.bid, log_command))
                self.cs_process.expect('.*aggressor.*> ')

            # run the command
            self.do_shell(command)

    # configure auto complete on the beacon_exec command
    complete_beacon_exec = Cmd.shell_cmd_complete


if __name__ == '__main__':

    app = RedShell()
    sys.exit(app.cmdloop())
