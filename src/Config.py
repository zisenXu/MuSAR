# Mode
MODE = "msas" # current database: cptc | msas

# database connection
connect_host = ""
connect_port = 
connect_user = ""
connect_pass = ""
if MODE == 'msas':
    db_name = ""
elif MODE == 'cptc':
    db_name = ''

if MODE == 'cptc':
    whiteList = ['10.0.1.54', '10.0.1.44', '10.0.1.46', '10.0.1.42', '10.0.1.51', '10.0.1.43', '10.0.1.40', '10.0.1.5', '10.0.1.52', '10.0.1.41', '10.0.1.53', '10.0.47.18', '10.0.47.21', '10.0.47.33', '10.0.47.87', '10.0.47.114', '10.0.47.128', '10.0.47.135', '10.0.47.136', '10.0.47.177', '10.0.47.190', '10.0.254.201', '10.0.254.202', '10.0.254.203', '10.0.254.204', '10.0.254.205', '10.0.254.206', '10.0.254.101', '10.0.254.102', '10.0.254.103', '10.0.254.104', '10.0.254.105', '10.0.254.106', '10.0.0.21', '10.0.0.23', '10.0.0.12', '10.0.0.11', '10.0.0.176', '10.0.0.24', '10.0.0.20', '10.0.0.10', '10.0.0.240', '10.0.0.241', '10.0.0.243', '10.0.0.244', '10.0.0.22']
elif MODE == 'msas':
    whiteList = [
        "192.168.50.5",
        "192.168.50.60",
        "192.168.9.101",
        "192.168.9.102",
        "192.168.9.103",
        "192.168.9.104",
        "192.168.9.105",
    ]


IANA_CSV_FILE_PATH = "./utils/service-names-port-numbers.csv"
EPISODE_WINDOW_LENGTH = 150  # window length to aggregate inter-host abnormal episodes
READ_BEHAVIOR_FROM_DATABASE = True # read intra-host sensitive behaviors from database
RESERVED = 1
NETWORK_EPISODE = 1 
HOST_BEHAVIOUR = 2 
NON_MALICIOUS = 0