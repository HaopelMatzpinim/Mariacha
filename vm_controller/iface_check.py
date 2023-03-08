from fabric import Connection, Config
import re

IPS = ["51.124.212.247", "20.160.62.51", "20.160.62.176", "20.123.133.179", "20.160.62.88", "52.233.224.141", "52.143.49.67", "20.229.89.198"]
USERNAME = "MazpinAdmin"


def extract_ips(str):
    return [ip_address for ip_address in str.split() if is_ip_address(ip_address)]

def check_routes(conn, out_ips, in_ips):
    for in_ip in in_ips:
        involved_ips = extract_ips(conn.run("ip route get " + in_ip, hide=True).stdout)
        for involved_ip in involved_ips:
            if not (involved_ip in in_ips or involved_ip in out_ips):
                print("Unknown ip: " + involved_ip, ". Was trying to get to ip: " + in_ip)

def is_ip_address(str):
    return re.search("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", str)

def following_words(str, previous_word):
    word_lst = str.split()

    return [word_lst[index + 1] for index in range(len(word_lst)) if index != (len(word_lst) - 1) and word_lst[index] == previous_word]

def mv_interfaces(conn):
    interface_ips = following_words(conn.run("ifconfig", hide=True).stdout, "inet")

    return [valid_interface for valid_interface in interface_ips if valid_interface != "127.0.0.1" and is_ip_address(valid_interface)]

def check_machines(ip1, ip2):
    print("\nChecking connection between MVs " + ip1 + " and " + ip2)
    conn1 = get_connection(ip1, USERNAME, PASSWORD)
    conn2 = get_connection(ip2, USERNAME, PASSWORD)
    mv1_interfaces = mv_interfaces(conn1)
    mv2_interfaces = mv_interfaces(conn2)
    check_routes(conn1, mv1_interfaces, mv2_interfaces)
    check_routes(conn2, mv2_interfaces, mv1_interfaces)


def get_connection(ip, username, password):
    return Connection(ip, user=username, connect_kwargs={'password': password})


for ip_index in range(0, 4):
    ip1, ip2 = IPS[ip_index], IPS[ip_index + 4]
    check_machines(ip1, ip2)
