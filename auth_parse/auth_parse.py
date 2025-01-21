import json
import pandas as pd
import os
import re

# parse user from various lines
def ParseUsr(line):
    usr = None
    if "Accepted password" in line:
        usr = re.search(r'(\bfor\s)(\w+)', line)
    elif "sudo:" in line:
        usr = re.search(r'(sudo:\s+)(\w+)', line)
    elif "authentication failure" in line:
        usr = re.search(r'USER=\w+', line)
    elif "for invalid user" in line:
        usr = re.search(r'(\buser\s)(\w+)', line)
    if usr is not None:
        return usr.group(2)

# parse an IP from a line
def ParseIP(line):
    ip = re.search(r'(\bfrom\s)(\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)', line)
    if ip is not None:
        return ip.group(2)

# parse a date from the line
def ParseDate(line):
    date = re.search(r'^[A-Za-z]{3}\s*[0-9]{1,2}\s[0-9]{1,2}:[0-9]{2}:[0-9]{2}', line)
    if date is not None:
        return date.group(0)

# parse a command from a line
def ParseCmd(line):
    # parse command to end of line 
    cmd = re.search(r'(\bCOMMAND=)(.+?$)', line)
    if cmd is not None:
        return cmd.group(2)

def ParseService(line):
    service = re.search(r'(\w+)\[', line.split(' ')[5])
    if service is None:
        service = re.search(r'([^:]+):', line.split(' ')[5])
    return service.group(1)

def ParsePort(line):
    port = re.search(r'port (\d+)', line)
    if port is None:
        port = ""
    return port.group(1)


# begin parsing the passed LOG
def ParseLogs(line):

    service = ParseService(line)
    usr = ""
    result = ""
    source_ip = ""
    source_port = ""
    cmd = ""
    # match a login
    if "Accepted password for" in line:
        usr = ParseUsr(line)
        source_ip = ParseIP(line)
        source_port = ParsePort(line)
        result = "success"

    # match a failed login
    elif "Failed password for" in line:
        # parse user
        usr = ParseUsr(line)            
        source_ip = ParseIP(line)
        source_port = ParsePort(line)
        result = "fail"
        
    # match failed auth
    elif ":auth): authentication failure;" in line:
        # so there are three flavors of authfail we care about;
        # su, sudo, and ssh.  Lets parse each.
        usr = re.search(r'(\blogname=)(\w+)', line)
        result = "fail"
        if usr is not None:
            usr = usr.group(2)
        # parse a fail log to ssh
        if "(sshd:auth)" in line:
            # ssh doesn't have a logname hurr
            usr = ParseUsr(line)
        # parse sudo/su fails

    # match commands
    elif "sudo:" in line:
        # parse user
        usr = ParseUsr(line)
        cmd = ParseCmd(line)
        # append the command if it isn't there already
    return (service, usr, result, source_ip, source_port, cmd)