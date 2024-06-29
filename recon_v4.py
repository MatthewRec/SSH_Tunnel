import socket
import subprocess
import os
import math

def scan_ports(ip_address, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip_address, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def net_scan():
    ip_address = input("Enter the IP address to scan: ")
    ssh_port = input("Enter the SSH port (default is 22): ")
    if not ssh_port:
        ssh_port = 22
    else:
        ssh_port = int(ssh_port)

    username = input("Enter the SSH username: ")
    password = input("Enter the SSH password: ")

    mode = input("Choose the mode:\n1. Normal\n2. Proxy\n")

    if mode == "1":
        # Normal mode
        command = f"sshpass -p '{password}' ssh -p {ssh_port} {username}@{ip_address} ip addr"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        output, _ = process.communicate()

        output = output.decode()
        eth0_line = [line for line in output.split('\n') if 'eth0' in line]
        ip_address_line = [line for line in eth0_line if 'inet ' in line]
        if ip_address_line:
            internal_ip_parts = ip_address_line[0].split()[1].split('/')
            internal_ip = internal_ip_parts[0]
            cidr = internal_ip_parts[1]
            print(f"Internal IP address of {ip_address}: {internal_ip}/{cidr}")
        else:
            print(f"Failed to retrieve the internal IP address of {ip_address}")

    elif mode == "2":
        # Proxy mode
        proxychains_path = input("Enter the path to proxychains (default is 'proxychains'): ")
        if not proxychains_path:
            proxychains_path = "proxychains"

        command = f"{proxychains_path} sshpass -p '{password}' ssh -p {ssh_port} {username}@{ip_address} ip addr"
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        output, _ = process.communicate()

        output = output.decode()
        eth0_line = [line for line in output.split('\n') if 'eth0' in line]
        ip_address_line = [line for line in eth0_line if 'inet ' in line]
        if ip_address_line:
            internal_ip_parts = ip_address_line[0].split()[1].split('/')
            internal_ip = internal_ip_parts[0]
            cidr = internal_ip_parts[1]
            print(f"Internal IP address of {ip_address}: {internal_ip}/{cidr}")
        else:
            print(f"Failed to retrieve the internal IP address of {ip_address}")

    else:
        print("Invalid mode.")

    # Run lscan
    answer = input("Do you want to run lscan on this network? (y/n): ")
    if answer.lower() == 'y':
        command = f"proxychains ./lscan.sh {internal_ip}"
        subprocess.call(command, shell=True)

    #Ping_Sweep
    def ping_sweep():
        #The If statements are seperating based on the octets. From there they are subtracting in variables of 8
        #This is because each octet has the same subnets values
        #raw_ip is taking into account the different octets and just carrying those values to the sweep
        octets = internal_ip.split(".")
        if 25 <= cidr <= 32:
            mess = octets[3]
            cidr_new = cidr-24
            raw_ip = f"{octets[0]}.{octets[1]}.{octets[2]}."
        elif 17 <= cidr <= 24:
            cidr_new = cidr-16
            mess = octets[2]
            raw_ip = f"{octets[0]}.{octets[1]}."
            raw_ip2 = f".{octets[3]}"
        elif 9 <= cidr <= 16:
            cidr_new = cidr-8
            mess = octets[1]
            raw_ip = f"{octets[0]}."
            raw_ip2 = f".{octets[2]}.{octets[3]}"

        # Compiling all the subnets
        def subnets():
            #This is taking the subnet masks and dividing by the number of hosts allowed in each mask
            #From there it is rounding up and down to find the range for that particular number's subnet range
            if cidr_new == 8:
                temp = int(mess)/256
                up = math.ceil(temp)*256
                down = math.floor(temp)*256
            elif cidr_new == 7:
                temp = int(mess)/128
                up = math.ceil(temp)*128
                down = math.floor(temp)*128
            elif cidr_new == 6:
                temp = int(mess)/64
                up = math.ceil(temp)*64
                down = math.floor(temp)*64
            elif cidr_new == 5:
                temp = int(mess)/32
                up = math.ceil(temp)*32
                down = math.floor(temp)*32
            elif cidr_new == 4:
                temp = int(mess)/16
                up = math.ceil(temp)*16
                down = math.floor(temp)*16
            elif cidr_new == 3:
                temp = (mess)/8
                up = math.ceil(temp)*8
                down = math.floor(temp)*8
            elif cidr_new == 2:
                temp = (mess)/4
                up = math.ceil(temp)*4
                down = math.floor(temp)*4
            elif cidr_new == 1:
                temp = (mess)/2
                up = math.ceil(temp)*2
                down = math.floor(temp)*2
            return up, down
        
        #This is running the ping sweep
        test = input("Would you like to run a Ping Sweep on the private network? (y/n): ")
        if answer.lower() == 'y':
            down, up = subnets()
            for i in range(down, up):
                ip = raw_ip + str(i) + raw_ip2
                command = f"ping -c1 {ip} | grep 'bytes from' &"
                subprocess.run(command, shell=True)          

def port_checker():
    ip_address = input("Enter the IP address to scan: ")
    port_str = input("Enter the ports to scan (space-separated): ")
    ports = [int(port) for port in port_str.split()]

    open_ports = scan_ports(ip_address, ports)
    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("No open ports found.")

def run_ftp_grab(ip_address):
    command = f"proxychains wget -r ftp://{ip_address}"
    subprocess.call(command, shell=True)

def run_http_grab(ip_address):
    command = f"proxychains wget -r http://{ip_address}"
    subprocess.call(command, shell=True)

def ftp_http_grabber():
    while True:
        print("\nFTP/HTTP Grabber Menu:")
        print("1. FTP Grab")
        print("2. HTTP Grab")
        print("3. Grab Both")
        print("4. Back to Menu")

        choice = input("Choose an option: ")
        if choice == "1":
            hfip = input("Enter the IP address for FTP grab: ")
            run_ftp_grab(hfip)
        elif choice == "2":
            hfip = input("Enter the IP address for HTTP grab: ")
            run_http_grab(hfip)
        elif choice == "3":
            hfip = input("Enter the IP address for FTP/HTTP grab: ")
            run_ftp_grab(hfip)
            run_http_grab(hfip)
        elif choice == "4":
            break
        else:
            print("Invalid choice.")

def Local():
    while True:
        #Will need to change the student and base port number when a new person is on the code
        student = "net2_student14@"
        port = [14000]
        Type = input("Is this your Tunnel? Y/N")
        IP = input("What is the IP you are connecting to? ")
        SSH = input("What SSH Port are you using to connect? ")

        if Type == "Y":
                print(f"You have successfully made a tunnel from your Jump Box to {IP}\nusing port {port}")
                subprocess.run(['ssh', f'{student}{IP}', '-L', f'{port}:localhost:{SSH}', '-NT'])
        elif Type == "N":
            last_port = input('Tunnel port # to your pivot box? ')
            new_port = input('New tunnel port # to target box? ')
            SSH = input("What SSH Port are you using to connect? ")
            print(f"You have successfully made a tunnel to {IP}\nUsing port {last_port}\nAnd claiming this new port {new_port}")
            subprocess.run(['ssh', f'{student}localhost', '-p', f'{last_port}', '-L', f'{new_port}:{IP}:{SSH}', '-NT'])
        else:
            print("Do you want to go back to Main Menu?")
            answer = input("To Confirm press Y")
            if answer == "Y":
                Tunneling_Option()
            else:
                Local()

def Dynamic():
    while True:
        #Will need to change the student and base port number when a new person is on the code
        student = "net2_student14@"
        port = [14000]
        Type = input("Is this your Tunnel? Y/N")
        IP = input("What is the IP you are connecting to? ")
    
        if Type == "Y":
            print(f"You have successfully made a dynamic tunnel to {IP}")
            subprocess.run(['ssh', f'{student}{IP}', '-D', '9050'])
        elif Type == "N":
            last_port = input('What Tunnel is taking you to the pivot box? ')
            print(f"You have successfully made a dynamic tunnel to {IP}")
            subprocess.run(['ssh', f'{student}localhost', '-p', f'{last_port}', '-D', '9050'])
        else:
            print("Do you want to go back to Main Menu?")
            answer = input("To Confirm press Y")
            if answer == "Y":
                Tunneling_Option()
            else:
                Dynamic()

def Remote():
    while True:
        #Will need to change the student and base port number when a new person is on the code
        student = "net2_student14@"
        port = [14000]
        Type = input("Is this your Tunnel? Y/N")
        IP = input("What is the IP you are connecting to? ")

        if Type == "Y":
            pivot_box_ip = input('What is your jump box IP? ')
            telnet_port = int(input('What RHP # do you want to use to set a Local port to the telnet box? '))
            print('\n' * 80, 'You need to open a new tab and run this command:\n')
            print(f'telnet {IP}', '\n\tThis will take you into the target box using telnet')
            print('~' * 20, '\nRun this from inside the target box:\n')
            print(f'ssh {student}{pivot_box_ip} -R {telnet_port+1}:localhost:22 -NT')
            print('\tThis is opening port 22 on the target box')
            print('~' * 80, '\nNow open a new tab and run this:\n')
            print(f'ssh {student}localhost -L {telnet_port+2}:localhost:{telnet_port+1} -NT')
            print('\t', f'{telnet_port+2} is the ssh tunnel to the target box')
            subprocess.run(['ssh', f'{student}{IP}', '-L', f'{telnet_port}:localhost:23', '-NT'])
        elif Type == "N":
            last_port = input('Tunnel port # to your pivot box? ')
            pivot_box_ip = input('What is your pivot box IP? ')
            SSH = input("What SSH Port are you using to connect? ")
            telnet_port = int(input('What RHP # do you want to use to set a Local port to the telnet box? '))
            print('\n' * 80, 'You need to open a new tab and run this command:\n')
            print(f'telnet {IP}', '\n\tThis will take you into the target box using telnet')
            print('~' * 20, '\nRun this from inside the target box:\n')
            print(f'ssh {student}{pivot_box_ip} -p {SSH} -R {telnet_port+1}:localhost:22 -NT')
            print('\tThis is opening port 22 on the target box')
            print('~' * 80, '\nNow open a new tab and run this:\n')
            print(f'ssh {student}localhost -p {last_port} -L {telnet_port+2}:localhost:{telnet_port+1} -NT')
            print('\t', f'{telnet_port+2} is the ssh tunnel to the target box')
            subprocess.run(['ssh', f'{student}localhost', '-p', f'{last_port}', '-L', f'{telnet_port}:{IP}:23', '-NT'])
        else:
            print("Do you want to go back to Main Menu?")
            answer = input("To Confirm press Y")
            if answer == "Y":
                Tunneling_Option()
            else:
                Remote()
            
def Tunneling_Option():
    while True:
        print("\nMenu:")
        print("1. Local Port")
        print("2. Dynamic Port")
        print("3. Remote Port")
        print("4. Back")
        

        tunnel = input("Choose an option: ")

        if tunnel == "1":
            Local()
        if tunnel == "2":
            Dynamic()
        if tunnel == "3":
            Remote()
        if tunnel == "4":
            main_menu()

def main_menu():
    while True:
        print("\nMenu:")
        print("1. Port Checker")
        print("2. FTP/HTTP Grabber")
        print("3. Net Scan")
        print("4. Tunneling")
        print("5. Exit")

        choice = input("Choose an option: ")

        if choice == "1":
            port_checker()
        elif choice == "2":
            ftp_http_grabber()
        elif choice == "3":
            net_scan()
        elif choice == "4":
            Tunneling_Option()
        elif choice == "5":
            print("Exiting the script.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main_menu()
