import re
import bashlex
from utils import *

class CmdParser:
    
    def __init__(self, cmdline) -> None:
        self.cmdline = cmdline
        self.command = None
        self.parsed_args = []
        self.input = None
        self.output = None
        self.target = []
        self.sensitive = 0
        self.parsed_result = []
        self.command_type = None

    def init_cmd_structure(self):  
        self.command = None
        self.parsed_args = []
        self.input = None
        self.output = None
        self.target = []
        self.sensitive = 0
        self.command_type = None

    def parse_cmdline(self, cmd):  # parse the syntax structure of bash commands，extract args and key entities
        pattern = re.compile(r'^(--?[\w|-]+)(=.+)?')
        parts = list(bashlex.split(cmd))
        if len(parts) == 0:
            return None, None
        command = parts[0]
        if command in ['sudo', 'nohup'] and len(parts) > 1:
            command = parts[1]
            args = parts[2:]
        elif command in ["pip", "pip3", "make"] and len(parts) > 1:
            command = " ".join(parts[:2])
            args = parts[2:]
        else:
            args = parts[1:]

        parsed_args = []
        none_flag = 1
        i = 0
        while i < len(args):
            arg = args[i]
            matches = pattern.findall(arg)
            if matches:
                option = matches[0][0]
                if matches[0][1]:  # --option=value
                    param = matches[0][1].strip('=')
                    parsed_args.append((option, param))
                    i += 1
                elif i+1 < len(args) and not re.match(pattern, args[i+1]): # -option value
                    param = args[i+1]
                    parsed_args.append((option, param))
                    i += 2
                else:
                    parsed_args.append((option, None)) # no args like "ls -l"
                    i += 1
            else:
                parsed_args.append((none_flag, arg))
                none_flag += 1
                i += 1
        return command, parsed_args

    # determine whether the intra-host operation is sensitive
    def is_sensitive(self, cmd):
        for stage, operation_list in sensitive_operations.items():
            if self.command in operation_list:
                self.sensitive = 1
                self.command_type = stage
                return
        
        for stage, semantic_list in sensitive_semantics.items():
            for semantic in semantic_list:
                if semantic in cmd:
                    self.sensitive = 1
                    self.command_type = stage
                    return
        
        for sensitive_file in sensitive_files:
            file_name = sensitive_file.split("/")[-1]
            if file_name in cmd and not file_name.isdigit():
                self.sensitive = 1
                self.command_type = "Collection"
                return

    def parse_command(self, command): 
        if command.startswith("./"): 
            self.command = "bash"
            self.input = command[2:]
        else:
            self.command = command

    def parse_input_output(self, parsed_args):  # identify input and output entities
        for index, arg in enumerate(parsed_args):
            if self.input is None:
                if index == 0 and (type(arg[0]) is int or re.match(r".+?\..+?", str(arg[1]))):
                    self.input = arg[1]
                elif index > 0 and parsed_args[index-1][1] in ["<", "<<"]:
                    self.input = arg[1]
                elif arg[0] in ["-r", "-i"]:
                    self.input = arg[1]
            if index > 0 and parsed_args[index-1][1] in [">", ">>"]:
                self.output = arg[1]
            elif arg[0] in ["-w", "-o", "-l", "-oN", "--outFile", "-O"]:
                self.output = arg[1]
        if self.output is None:
            self.output = "stdout"

    def special_command_parse(self, command, parsed_args):
        if command in ["tar", "zip", "unzip"]:
            pattern = re.compile(r".*?(zip|tar|tar\.gz)$")
            for index, arg in enumerate(parsed_args):
                if arg[1] is None:
                    continue
                if re.match(pattern, arg[1]):
                    self.input = arg[1]
                    break
        if command in ["chmod", "chown"]:
            if len(parsed_args) >= 2:
                self.input = self.output = parsed_args[1][1]
        if command in ["wget"]:
            for index, arg in enumerate(parsed_args):
                if arg[1] is None:
                    continue
                if "http" in arg[1] or '/' in arg[1]:
                    self.output = arg[1].split('/')[-1]
                    break
        if command in ["gcc", "g++"]:
            for index, arg in enumerate(parsed_args):
                if arg[1] is None:
                    continue
                if ".c" in arg[1] or ".cpp" in arg[1]:
                    self.input = arg[1]
                    break
        if command in ["python", "python3"]:
            for index, arg in enumerate(parsed_args):
                if arg[1] is None:
                    continue
                if ".py" in arg[1]:
                    self.input = arg[1]
                    break
        if command in ["bash", "/bin/sh", "/bin/bash", "sh"]:
            for index, arg in enumerate(parsed_args):
                if arg[1] is None:
                    continue
                if ".sh" in arg[1]:
                    self.input = arg[1]
                    break

    # extract target entity
    def parse_target(self, cmd):
        ips = extractIPAddresses(cmd)
        if ips is not False:
            self.target.extend(list(set(ips)))
        


    def parse(self):
        cmd_list = self.cmdline.split("|")
        for index, cmd in enumerate(cmd_list):
            if index >= 1:
                self.init_cmd_structure()
                self.input = self.parsed_result[-1]["output"]
            self.command, self.parsed_args = self.parse_cmdline(cmd) 
            if self.command is None and self.parsed_args is None:
                return False
            self.parse_command(command=self.command) 
            self.special_command_parse(command=self.command, parsed_args=self.parsed_args)
            self.parse_input_output(parsed_args=self.parsed_args)
            self.parse_target(cmd=cmd)
            self.is_sensitive(cmd)

            ## parsing results
            self.parsed_result.append({
                "command": self.command,
                "parsed_args": self.parsed_args,
                "input": self.input,
                "output": self.output,
                "target": self.target,
                "sensitive": self.sensitive,
                "command_type": self.command_type
            })