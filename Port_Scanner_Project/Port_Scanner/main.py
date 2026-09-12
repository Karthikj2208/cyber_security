import socket
import csv
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
RESULTS = BASE / 'results'

COMMON_SERVICES = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',8080:'HTTP-Alt'
}

def scan_port(host, port, timeout=0.5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((host, port))
        return result == 0
    except (socket.timeout, OSError):
        return False
    finally:
        s.close()

def service_name(port):
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, 'tcp').upper()
    except OSError:
        return 'Unknown'

def export_results(target, results):
    RESULTS.mkdir(exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_file = RESULTS / f'scan_{stamp}.csv'
    txt_file = RESULTS / f'scan_{stamp}.txt'
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Target','Port','State','Service'])
        for r in results:
            writer.writerow([target, r['port'], r['state'], r['service']])
    with open(txt_file, 'w', encoding='utf-8') as f:
        f.write(f'Port Scan Report\nTarget: {target}\nTime: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n')
        for r in results:
            f.write(f"Port {r['port']}: {r['state']} - {r['service']}\n")
    return csv_file, txt_file

def main():
    print('='*58)
    print('                 PYTHON PORT SCANNER')
    print('='*58)
    print('Use only on systems you own or have permission to test.\n')
    target = input('Target IP or hostname [127.0.0.1]: ').strip() or '127.0.0.1'
    try:
        host = socket.gethostbyname(target)
    except socket.gaierror:
        print('Could not resolve the target.')
        return
    try:
        start = int(input('Start port [1]: ').strip() or '1')
        end = int(input('End port [100]: ').strip() or '100')
    except ValueError:
        print('Ports must be numbers.')
        return
    if not (1 <= start <= end <= 65535):
        print('Use a valid range between 1 and 65535.')
        return
    print(f'\nScanning {target} ({host}) ports {start}-{end}...\n')
    results=[]
    for port in range(start, end+1):
        if scan_port(host, port):
            service = service_name(port)
            results.append({'port':port,'state':'OPEN','service':service})
            print(f'[OPEN] {port:5}  {service}')
    if not results:
        print('No open TCP ports found in the selected range.')
    csv_file, txt_file = export_results(target, results)
    print('\nScan completed.')
    print(f'CSV report: {csv_file}')
    print(f'TXT report: {txt_file}')

if __name__ == '__main__':
    main()
