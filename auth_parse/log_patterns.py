'''
Anomalous Log Patterns extracting from the authentication logs of the SSH daemon (sshd), which records user login attempts, successful logins, failures, etc. 

The main categories of security events extracted are as follows:

1. Authentication Failure: Failed authentication attempts that can be divided into different attack stages based on the login username.
Example: Nov  3 23:23:16 talk-00 sshd[15893]: PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.254.206  user=root.

2. Pre-authentication Failure: Events mainly caused by non-existent login usernames. If more than five occurrences from the same source IP address happen within a short period, it's judged as an attempted brute force attack.
Example: Nov  3 22:50:20 nationals-t1-prod-trackdash-00 sshd[17215]: error: Received disconnect from 10.0.254.103 port 17723:3: com.jcraft.jsch.JSchException: Auth fail [preauth]

3. Login Error: Failed illegal user logins marked by "Failed password for <username>" or "Failed none for invalid user". Similar to the previous event type, if more than five occurrences from the same source IP address happen within a short time, it's considered an attempted brute force attack.
Example: Nov  3 22:42:40 nationals-t1-corp-onramp-00 sshd[21273]: Failed password for invalid user super from 10.0.254.202 port 56763 ssh2

4. Invalid User: Failed illegal login attempts due to non-existent users, similar to the above category.
Example matches the "Login Error" example.

5. Invalid Public Key (userauth_pubkey): Client login attempts using a public key that does not meet server requirements.
Example: Nov  3 22:42:37 nationals-t1-corp-onramp-00 sshd[21267]: userauth_pubkey: key type ssh-dss not in PubkeyAcceptedKeyTypes [preauth]

6. Successful Login: Successful login attempts.
Example: Nov  3 22:15:20 mail-00 sshd[4839]: Accepted password for murray.rohman from 10.0.254.206 port 53686 ssh2

'''

feature_dict = {
    "pam_unix\(sshd:auth\): authentication failure": 0,
    "Auth fail \[preauth\]": 1,
    "Failed password for": 2,
    "Failed none for invalid user": 3,
    ": Invalid user": 4,
    "Accepted password for": 5,
    "Accepted publickey for ": 6
}

category_dict = {
    0: "Attempted User Privilege Gain",
    1: "Attempted User Privilege Gain",
    2: "Attempted User Privilege Gain",
    3: "Attempted User Privilege Gain",
    4: "Attempted User Privilege Gain",
    5: "Attempted User Privilege Gain",
    6: "Attempted User Privilege Gain"
}

signature_dict = {
    0: "Authentication failure for existed user",
    1: "potential account cracking for unexisted user",
    2: "potential account cracking for unexisted user",
    3: "potential account cracking for unexisted user",
    4: "potential account cracking for unexisted user",
    5: "remote login successfully",
    6: "remote login successfully"
}

severity_dict = {
    0: 2,
    1: 2,
    2: 2,
    3: 2,
    4: 2,
    5: 3,
    6: 3
}