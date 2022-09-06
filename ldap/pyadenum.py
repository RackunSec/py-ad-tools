#!/usr/bin/env python3
# pyADEnum
# 2022 @RackunSec
#
import ldap3 # for LDAP
import sys # for args, exit
import os # for file stuff

# Display how to use the script:
def usage():
    print("Usage: python3 pyADEnum.py (DC HOST LIST)")
    sys.exit(1)

# Display error messages:
def error(msg):
    print(f"[!] Error: {msg}")

def enum(host,port):
    if port == 636:
        use_ssl = True
    else:
        use_ssl = False
    path_dir = "./log-pyadenum/"
    if not os.path.exists(path_dir):
        os.mkdir(path_dir)
    server = ldap3.Server(host, get_info = ldap3.ALL, port =port, use_ssl = use_ssl)
    connection = ldap3.Connection(server)
    if connection.bind(): # Connection was successful
        logfile = path_dir+host+"."+str(port)+".info.txt"
        print(f"[i] Connection successful!\n[i] Gathering information into {logfile}")
        with open(logfile,"w") as log:
            log.write(repr(server.info))
            log.write("\n")
            all_data = connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
            if(all_data): # Will be False if nothing
                log.write(repr(all_data))
                log.write("\n")
            else:
                error(f"Could not get all data with anonymous connection from {host}:{port}")
            all_data = connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=person))', search_scope='SUBTREE', attributes='userPassword')
            if(all_data):
                log.write(repr(all_data))
            else:
                error(f"Could not get Person class with anonymous bind from {host}:{port}")
            print()
            return # Done.
    else:
        error(f"Could not connect to {host}@{port}")
        return

# Our main() function:
def main():
    if len(sys.argv) != 2:
        usage();
    else:
        dclist = sys.argv[1]
        if os.path.exists(dclist):
            # Open the file and start checking hosts
            print(f"[i] Using DC Host list {dclist}")
            with open(dclist) as file:
                hosts = file.readlines() # read in all lines into array
                hosts = [host.rstrip() for host in hosts] # remove newlines
            for host in hosts:
                print(f"[i] Attempting port 389 anonymous bind with {host}")
                enum(host,389)
                print(f"[i] Attempting port 636 anonymous bind with {host}")
                enum(host,636)
        else:
            error(f"Could not open File for reading: {dclist}")
            usage()


if __name__ == "__main__":
    main()
