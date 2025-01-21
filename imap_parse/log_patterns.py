"""
dovecot: imap-login: Disconnected: Too many invalid command
dovecot: imap-login: Disconnected (auth failed,
dovecot: imap-login: Login:
"""


feature_dict = {
    "imap-login: Disconnected: Too many invalid commands": 0,
    "imap-login: Disconnected \(auth failed": 1,
    "imap-login: Login:" : 2
}

category_dict = {
    0: "Web Application Attack",
    1: "Attempted User Privilege Gain",
    2: "access to a potentially vulnerable web application"
}

signature_dict = {
    0: "IMAP Vulnerability Attack Attempt",
    1: "IMAP Password Cracking",
    2: "IMAP Successfully Log in"
}

severity_dict = {
    0: 1,
    1: 1,
    2: 3
}