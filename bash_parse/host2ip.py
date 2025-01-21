host_dict = {
    'prod-memcache-13': '10.0.1.54',
    'prod-money-00': '10.0.1.44',
    'prod-trackdash-00': '10.0.1.46',
    'prod-routing-00': '10.0.1.42',
    'prod-postgres-00': '10.0.1.51',
    'prod-safety-00': '10.0.1.43',
    'prod-dapi-00': '10.0.1.40',
    'prod-frontend-00': '10.0.1.5',
    'prod-geo-04': '10.0.1.52',
    'prod-lapi-00': '10.0.1.41',
    'prod-geo-05': '10.0.1.53',
    'cars-car-18': '10.0.47.18',
    'cars-car-21': '10.0.47.21',
    'cars-car-33': '10.0.47.33',
    'cars-car-87': '10.0.47.87',
    'cars-car-114': '10.0.47.114',
    'cars-car-128': '10.0.47.128',
    'cars-car-135': '10.0.47.135',
    'cars-car-136': '10.0.47.136',
    'cars-car-177': '10.0.47.177',
    'cars-car-190': '10.0.47.190',
    'vdi-kali01': '10.0.254.201',
    'vdi-kali02': '10.0.254.202',
    'vdi-kali03': '10.0.254.203',
    'vdi-kali04': '10.0.254.204',
    'vdi-kali05': '10.0.254.205',
    'vdi-kali06': '10.0.254.206',
    'vdi-win01': '10.0.254.101',
    'vdi-win02': '10.0.254.102',
    'vdi-win03': '10.0.254.103',
    'vdi-win04': '10.0.254.104',
    'vdi-win05': '10.0.254.105',
    'vdi-win06': '10.0.254.106',
    'corp-people-00': '10.0.0.21',
    'corp-audit-00': '10.0.0.23',
    'corp-wiki-00': '10.0.0.12',
    'corp-helpdesk-00': '10.0.0.11',
    'corp-onramp-00': '10.0.0.176',
    'corp-security-00': '10.0.0.24',
    'corp-talk-00': '10.0.0.20',
    'corp-ad-00': '10.0.0.10',
    'corp-employee-00': '10.0.0.240',
    'corp-employee-01': '10.0.0.241',
    'corp-employee-02': '10.0.0.243',
    'corp-employee-03': '10.0.0.244',
    'corp-mail-00': '10.0.0.22'
}

domain_dict = {
    'payments.wheelzapp.com': 'prod-money-00',
    'routing-00.prod.wheelzapp.com': 'prod-routing-00',
    'wiki.wheelzapp.com': 'corp-wiki-00',
    'trackdash-00.prod.wheelzapp.com':  'prod-trackdash-00',
    'memcache-13.prod.wheelzapp.com': 'prod-memcache-13',
    'ad-00.corp.wheelzapp.com': 'corp-ad-00',
    'frontend-00.prod.wheelzapp.com': 'prod-frontend-00',
    'dapi-00.prod.wheelzapp.com': 'prod-dapi-00',
    'lapi-00.prod.wheelzapp.com': 'prod-lapi-00',
    'safety-00.prod.wheelzapp.com': 'prod-safety-00',
    'money-00.prod.wheelzapp.com': 'prod-money-00',
    

}


def host2ip(host):
    ip = host_dict[host]
    return ip


def ip2host(ip):
    for key, value in host_dict.items():
        if value == ip:
            return key
    return "unknown"