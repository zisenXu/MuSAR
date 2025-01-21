"""
[listener] connection accepted from 10.0.254.206:60168 #27 (21 connections now open)
[conn27] received client metadata from 10.0.254.206:60168 conn: { application: { name: "MongoDB Shell" }, driver: { name: "MongoDB Internal Client", version: "3.6.3" }, os: { type: "Linux", name: "Kali", architecture: "x86_64", version: "kali-rolling" } }
[conn27] end connection 10.0.254.206:60168 (20 connections now open)
"""

feature_dict = {
    "received client metadata from.*?{ name: \"MongoDB Shell\" }": 0
}

category_dict = {
    0: "Successful Administrator Privilege Gain",
}

signature_dict = {
    0: "MongoDB interactive shell connection and privilege gain",
}

severity_dict = {
    0: 3,
}