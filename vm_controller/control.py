from fabric import Connection, Config
from concurrent.futures import ThreadPoolExecutor
from itertools import repeat

IPS = ["51.124.212.247", "20.160.62.51", "20.160.62.176", "20.123.133.179", "20.160.62.88", "52.233.224.141", "52.143.49.67", "20.229.89.198"]
USER = "MazpinAdmin"


def connect_to_vm(ip, user, password):
    return Connection(ip, user=user, connect_kwargs={'password': password})

def execute_command(conn, cmd):
    try:
        cmd_out = conn.run(cmd, hide=True).stdout
    except Exception as e:
        cmd_out = e

    return cmd_out

connections = [connect_to_vm(vm_ip, USER, PASSWORD) for vm_ip in IPS]
executor = ThreadPoolExecutor()

cmd = input("Enter command: ")

while cmd.lower() != 'exit':
    results = executor.map(execute_command, connections, repeat(cmd))

    for ip, result in zip(IPS, results):
        print("VM " + ip + ":")
        print(result, end='\n')

    cmd = input("Enter command: ")
