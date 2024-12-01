# By Jester-binn

# Imports
import socket
import sys
import datetime
import os


# Ports list
tcp_ports_description__list = {}
udp_ports_description__list = {}

# Software parameters
software_parameters = {

    'timeout': 0.01,
    'save result in file': False,
    'show close ports': False,

    'protocol': 'all',

    'ip': None,

    'port': None,
    'ports range': None,
    'ports file': None

}

# Software help text
software_help_text = '''
J-portscan ~ HELP

syntaxis: python main.py <parameters[--t/--s/--g]> <port[-p/-r/-f]> <protocol[--tcp/--udp/default]> <[ip]>

Use -p <port> <ip>, to scan one port

Use --tcp <ip>, to scan all TCP ports
Use --upd <ip>, to scan all UDP ports

Use -r n1 n2 <ip>, to scan all ports from n1 to n2  
Use --tcp -r n1 n2 <ip>, to scan only TCP ports from n1 to n2 
Use --udp -r n1 n2 <ip>, to scan only UDP ports from n1 to n2 

Use -f <path to file with ports> <ip>, to scan all ports from file 
Use --tcp -f <path to file with ports>  <ip>, to scan only TCP ports from file 
Use --udp -f <path to file with ports>  <ip>, to scan only UDP ports from file 

Use --t <float number>, to specify timeout for connect to ip:port, default 0.01
Use --s, if you want to software will write result in file
Use --g, if you want to software will show close ports 
'''

# Ports status
open_ports = []
close_ports = []

# Time start and finish scanning
start_scanning_time = {'hour': 0, 'minute': 0, 'second': 0, 'date': ''}
finish_scanning_time = {'hour': 0, 'minute': 0, 'second': 0, 'date': ''}


# Get time and date now
def get_date_time():
    dt = datetime.datetime.now()
    result = {
        'hour': dt.hour,
        'minute': dt.minute,
        'second': dt.second,

        'date': dt.date()
    }
    return result


# Print info in console from name software
def print_info(text):
    print(f'\n┏━━J-Portscan.py ~ [https://t.me/Jester_binn]\n┗━{str(text)}\n')


# Open ports with ports description and load
def load_ports_lists():
    """Load all ports from file tcp_ports.txt
     and udp_ports.txt. Split and append to list
     in format {port: description}"""

    # Check TCP ports
    try:
        with open('tcp_ports.txt', 'r', encoding='utf-8') as file:
            for line in file:
                split_line = line.split()
                port_F = int(split_line[1])
                description_F = str(split_line[2])
                tcp_ports_description__list[port_F] = description_F

        # Check UDP ports
        with open('udp_ports.txt', 'r', encoding='utf-8') as file:
            for line in file:
                split_line = line.split()
                port_F = int(split_line[1])
                description_F = str(split_line[2])
                udp_ports_description__list[port_F] = description_F
    except FileNotFoundError:
        print_info('Error: file tcp_ports.txt or udp_ports.txt not found!')


# Check port errors
def check_port(port):
    try:
        port = int(port)
        if not (0 <= port <= 65535):
            print_info(f'Error: -p {port} is not 0 <= port <= 65535!')
            quit()
        return port
    except ValueError:
        print_info(f'Error: -p {port}, invalid port!')
        quit()


# Check ports range errors
def check_port_range(ports_range: tuple):
    try:
        number_a = int(ports_range[0])
        number_b = int(ports_range[1])

        if number_a > number_b:
            temp = number_a
            number_a = number_b
            number_b = temp

        return number_a, number_b
    except ValueError:
        print_info(f'Error: -r {ports_range[0]} {ports_range[1]},{ports_range[0]} or {ports_range[1]} not integer!')
        quit()
    except KeyError:
        print_info(f'Error: -r <error>, invalid ports range!')
        quit()


# Check timeout errors
def check_time_out(timeout):
    try:
        timeout = float(timeout)
        return timeout
    except ValueError:
        print_info(f'Error: --t {timeout}, {timeout} is not float number!')
        quit()


# Check ip address error
def check_ip_address(ip_address):
    try:
        host_name = socket.gethostbyname(str(ip_address))
        return ip_address
    except:
        print_info(f'Error: {ip_address}, invalid ip address!')
        quit()


# Check path to file with ports errors
def check_path_to_file_with_ports(path):
    ports_list = []

    if not str(path).endswith('.txt'):
        print(f'Error: file {path} is not txt!')
        quit()

    try:
        with open(path, 'r', encoding='utf-8') as file:
            for line in file:
                try:
                    ports_list.append(int(line))
                except ValueError:
                    print(f'Error: One of ports from file ({line}) is not integer')
                    quit()
            file.close()
            return ports_list
    except FileNotFoundError:
        print(f'Error: file {path} not found!')
        quit()
    except OSError:
        print(f'Error: file {path} is not txt!')
        quit()
    except UnicodeError:
        print(f'Error: Unicode error, file must be in utf-8!')
        quit()


# Scan port function
def scan_port(port):
    """Try to connect ti ip:port, if no errors return 1, port is open,
    else return 0 or error if error"""

    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection_timeout = software_parameters['timeout']
    try:
        soc.settimeout(connection_timeout)
        soc.connect((software_parameters['ip'], port))
        soc.close()
        return 1
    except ConnectionRefusedError:
        return 0
    except TimeoutError:
        return 0
    except OSError:
        return 0
    except NameError or ValueError:
        print_info('Error: invalid data!')
        quit()


# Get description of ports from lists
def get_port_description(port):
    """Find info about port in tcp and udp ports list"""
    if port in tcp_ports_description__list and port in udp_ports_description__list:
        port_protocol = '/TCP,UDP'
        port_description = tcp_ports_description__list[port]
    elif port in tcp_ports_description__list:
        port_protocol = '/TCP'
        port_description = tcp_ports_description__list[port]
    elif port in udp_ports_description__list:
        port_protocol = '/UDP'
        port_description = udp_ports_description__list[port]
    else:
        port_protocol = '   '
        port_description = 'Undefined'

    return {'protocol': port_protocol, 'description': port_description}


# Get all time of scan
def get_all_scan_time():
    all_scan_hour = finish_scanning_time['hour'] - start_scanning_time['hour']
    all_scan_minute = finish_scanning_time['minute'] - start_scanning_time['minute']
    all_scan_second = finish_scanning_time['second'] - start_scanning_time['second']
    all_scan_time = {
        'hour': all_scan_hour,
        'minute': all_scan_minute,
        'second': all_scan_second
                     }

    return all_scan_time


# Open and save result in file
def save_result_in_file():
    with open('result.txt', 'a+', encoding='utf-8') as file:
        file.write(f'\n\nScanning target {software_parameters['ip']}.\n'
                   f'Start at {start_scanning_time['hour']}:{start_scanning_time['minute']}, {start_scanning_time['second']}sec {start_scanning_time['date']}\n'
                   f'Finish at {finish_scanning_time['hour']}:{finish_scanning_time['minute']}, {finish_scanning_time['second']}sec {finish_scanning_time['date']}\n'
                   f'All scan time: {get_all_scan_time()['hour']} hours, {get_all_scan_time()['minute']} minutes and {get_all_scan_time()['second']} seconds\n')

        if len(open_ports) > 0:
            file.write(f'{software_parameters['protocol']} open ports in {software_parameters['ip']}\n')
            file.write('-----------\n')
            for open_port in open_ports:
                file.write(open_port + '\n')
        else:
            file.write('All port was close')
        file.close()


# Main function
def main():
    # Save data of start scanning
    get_dt = get_date_time()
    start_scanning_time['hour'] = get_dt['hour']
    start_scanning_time['minute'] = get_dt['minute']
    start_scanning_time['second'] = get_dt['second']
    start_scanning_time['date'] = str(get_dt['date'])

    print(f'\n[*] Start scanning target {software_parameters['ip']} by J-portscan 1.0.0 at {get_dt['hour']}:{get_dt['minute']} '
          f'{get_dt['second']}sec. {get_dt['date']}\n')


    # Start scanning
    print('Result will be in format: PORT STATUS DESCRIPTION')

    if software_parameters['port'] is not None:
        port = software_parameters['port']
        connection_response = scan_port(port)
        if connection_response == 1:
           port_description = get_port_description(port)
           print(f'[+] {port}{port_description['protocol']}    open     {port_description['description']}')
        elif connection_response == 0:
            if software_parameters['show close ports']:
                port_description = get_port_description(port)
                print(f'[-] {port}{port_description['protocol']}    close     {port_description['description']}')

    elif software_parameters['ports range'] is not None:
        number_a = software_parameters['ports range'][0]
        number_b = software_parameters['ports range'][1]

        open_ports_quantity = 0
        connection_response = ''

        for port in range(number_a, number_b+1):
            # Checking protocol
            if software_parameters['protocol'] == 'TCP':
                if port in tcp_ports_description__list:
                    connection_response = scan_port(port)
                else:
                    continue
            elif software_parameters['protocol'] == 'UDP':
                if port in udp_ports_description__list:
                    connection_response = scan_port(port)
                else:
                    continue
            elif software_parameters['protocol'] == 'all':
                connection_response = scan_port(port)

            # Print port status, description and protocol
            if connection_response == 1:
                open_ports_quantity += 1
                port_description = get_port_description(port)
                print(f'[+] {port}{port_description['protocol']}    open    {port_description['description']}')
            elif connection_response == 0:
                if software_parameters['show close ports']:
                    port_description = get_port_description(port)
                    print(f'[-] {port}{port_description['protocol']}    close    {port_description['description']}')

        # Print close port quantity, if software do not show close ports
        if not software_parameters['show close ports']:
            print(f'\n[*] {number_b-number_a-open_ports_quantity} closed ports were not shown')

    elif software_parameters['ports file'] is not None:
        open_ports_quantity = 0
        connection_response = ''

        for port in software_parameters['ports file']:
            # Checking protocol
            if software_parameters['protocol'] == 'TCP':
                if port in tcp_ports_description__list:
                    connection_response = scan_port(port)
                else:
                    continue
            elif software_parameters['protocol'] == 'UDP':
                if port in udp_ports_description__list:
                    connection_response = scan_port(port)
                else:
                    continue
            elif software_parameters['protocol'] == 'all':
                connection_response = scan_port(port)

            # Print port status, description and protocol
            if connection_response == 1:
                open_ports_quantity += 1
                port_description = get_port_description(port)
                print(f'[+] {port}{port_description['protocol']}    open     {port_description['description']}')
            elif connection_response == 0:
                if software_parameters['show close ports']:
                    port_description = get_port_description(port)
                    print(f'[-] {port}{port_description['protocol']}    close    {port_description['description']}')

        # Print close port quantity, if software do not show close ports
        if not software_parameters['show close ports']:
            print(f'\n[*] {len(software_parameters['ports file']) - open_ports_quantity} closed ports were not shown')


    # Save data of finish scanning
    get_dt = get_date_time()
    finish_scanning_time['hour'] = get_dt['hour']
    finish_scanning_time['minute'] = get_dt['minute']
    finish_scanning_time['second'] = get_dt['second']
    finish_scanning_time['date'] = str(get_dt['date'])

    print(f'\n[*] Finish scanning target {software_parameters['ip']} by J-portscan 1.0.0 at {get_dt['hour']}:{get_dt['minute']} '
          f'{get_dt['second']}sec. {get_dt['date']}.\n'
          f'[*] All scan time: {get_all_scan_time()['hour']} hour, {get_all_scan_time()['minute']} minutes and {get_all_scan_time()['second']} seconds\n')

    # Save result in file
    if software_parameters['save result in file']:
        save_result_in_file()
        print(f'[*] Result was save in {os.path.abspath('result.txt')}')


# Start software
if __name__ == '__main__':
    load_ports_lists()

    get_sys_args = sys.argv

    # Get help
    if len(get_sys_args) <= 1 or '-h' in get_sys_args:
        print(software_help_text)
        quit()

    # Get parameters
    if '--s' in get_sys_args:
        software_parameters['save result in file'] = True
    if '--g' in get_sys_args:
        software_parameters['show close ports'] = True

    # Get protocol
    if '--tcp' in get_sys_args and '--udp' in get_sys_args:
        print_info('Error: You entered two protocols, but you must enter one of --tcp or --udp')
        quit()
    elif '--tcp' in get_sys_args:
        software_parameters['protocol'] = 'TCP'
    elif '--udp' in get_sys_args:
        software_parameters['protocol'] = 'UDP'

    # Get ip address
    len__get_sys_args = len(get_sys_args)
    get_ip_address = get_sys_args[len__get_sys_args-1]
    get_ip_address = check_ip_address(get_ip_address)
    software_parameters['ip'] = get_ip_address

    # Get parameters
    for arg in get_sys_args:
        if str(arg) == '-p':
            get_port = get_sys_args[get_sys_args.index(arg)+1]
            get_port = check_port(get_port)
            software_parameters['port'] = get_port
        elif str(arg) == '-r':
            get_ports_range = (get_sys_args[get_sys_args.index(arg)+1], get_sys_args[get_sys_args.index(arg)+2])
            get_ports_range = check_port_range(get_ports_range)
            software_parameters['ports range'] = get_ports_range
        elif str(arg) == '-f':
            get_path_to_file_with_ports = get_sys_args[get_sys_args.index(arg)+1]
            get_path_to_file_with_ports = check_path_to_file_with_ports(get_path_to_file_with_ports)
            software_parameters['ports file'] = get_path_to_file_with_ports

        if str(arg) == '--t':
            get_timeout = get_sys_args[get_sys_args.index(arg)+1]
            get_timeout = check_time_out(get_timeout)
            software_parameters['timeout'] = get_timeout


    main()