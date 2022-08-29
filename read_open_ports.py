#!/usr/bin/python3

import merge_xml as MX
import sys
import os
import xml.etree.ElementTree as ET

def run_nmap(scan_data,nmap_args):
    #run nmap with ports for each host
    #temp xml files will be deleted
    for host in scan_data:
        if os.path.exists("%s_temp.xml" % (host)):
            print("Skipping %s...." % (host))
            continue
        print("nmap -p"+",".join(scan_data[host])+" %s %s -oX %s_temp.xml" % (nmap_args, host, host))
        os.system("nmap -p"+",".join(scan_data[host])+" %s %s -oX %s_temp.xml" % (nmap_args, host, host))
    merge_results()

def merge_results():
    xml_files = []
    path = os.getcwd()
    for each in os.listdir(path):
        if each.endswith("_temp.xml"):
            xml_files.append(each)
    MX.main(xml_files)
    #move temp files to archive
    #os.system('tar -cf temp_files.tar -T ')
    for each in xml_files:
        os.system('tar -r --file=temp_files.tar %s' % (each))
        os.remove(each)


def parse_nmap_xml(xml_data):
    print("Parsing ports for host(s)...")
    #create dict for scan data
    host_data = {}
    #read and parse port from xml 
    tree = ET.parse(xml_data)
    root = tree.getroot() # Parse XML
    #loop through each host
    for child in root:
        if child.tag == 'host' and child[0].attrib['state'] == 'up':
            host_data[child[1].attrib['addr']] = []
            for element in child:
                if element.tag == 'ports':
                    for port in element:
                        if port.tag == 'port':
                            if port[0].attrib['state'] == 'open':
                                #add port to list to be scanned
                                host_data[child[1].attrib['addr']].append(port.attrib['portid'])                                                     
                            elif port[0].attrib['state'] != 'open':
                                continue
                else:
                    continue
            
        elif child.tag != 'host':
            continue

    print("done parsing...")
    #print(host_data)
    return host_data
def main():
    try:
        print("nmap arguments: %s" % sys.argv[2])
    except:
        print("usage: %s <NMAP XML> <NMAP ARGS>" % sys.argv[0])
        print("example: %s ./host_port_scan.xml '-Pn -T3 -sV'" % sys.argv[0])
        print('No need to specify -oX, XML will automatically be generated')
        exit()

    nmap_args = sys.argv[2].strip()
    scan_data = parse_nmap_xml(sys.argv[1])
    run_nmap(scan_data,nmap_args)


if __name__ == "__main__":
    main()
