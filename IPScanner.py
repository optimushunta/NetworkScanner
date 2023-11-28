import scapy.all as scapy
import socket

def get_device_name(ip):
    try:
        # Get the device name using the IP address
        device_name = socket.gethostbyaddr(ip)[0]
        return device_name
    except Exception as e:
        print(f"Error getting device name for {ip}: {e}")
        return None

def scan(ip):
    # Create an ARP request packet
    arp_request = scapy.ARP(pdst=ip)
    # Create an Ethernet frame to broadcast the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # Send the packet and receive the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    # Create a list to store dictionaries of device information
    devices_list = []
    for element in answered_list:
        # Extract IP and MAC addresses from the response
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        # Get the device name based on the IP address
        device_info["name"] = get_device_name(device_info["ip"])
        devices_list.append(device_info)
    return devices_list

def print_result(devices_list):
    print("IP Address\t\tMAC Address\t\tDevice Name")
    print("----------------------------------------------------------")
    for device in devices_list:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}")

if __name__ == "__main__":
    target_ip_range = "192.168.0.1/24"  # Adjust the IP range based on your network configuration
    devices = scan(target_ip_range)
    print_result(devices)
