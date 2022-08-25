import xml.etree.cElementTree as ET
import sys

#read masscan files and output to dict
def read_masscan(xml_data):
	masscan_data={}
	mas_tree = ET.parse(xml_data)
	mas_root = mas_tree.getroot()
	masscan_data["start"]=mas_root.attrib['start']
	masscan_data["end"]=mas_root[-1][0].get('time')
	for child in mas_root:
		if child.tag == "host":
			if child[0].attrib['addr'] not in masscan_data.keys():
				masscan_data[child[0].attrib['addr']] = []
				if child[0].attrib['addrtype'] not in masscan_data[child[0].attrib['addr']]:
					masscan_data[child[0].attrib['addr']].append(child[0].attrib['addrtype'])

				if child[1][0][0].attrib['state'] == "open":
					tmp_port = [child[1][0].attrib['protocol'],child[1][0].attrib['portid'],child[1][0][0].attrib['state']]
					masscan_data[child[0].attrib['addr']].append(tmp_port)
			else:
				if child[1][0][0].attrib['state'] == "open":
					tmp_port = [child[1][0].attrib['protocol'],child[1][0].attrib['portid'],child[1][0][0].attrib['state']]
					masscan_data[child[0].attrib['addr']].append(tmp_port)

	print(masscan_data)

	return masscan_data


#convert masscan dict to nmap xml
def convert2nmap(data):
	c2n_root = ET.Element("nmaprun", start=data['start'])
	c2n_scaninfo = ET.SubElement(c2n_root, "scaninfo")

	for host in data:
		if host != "start" and host != "end":
			c2n_host = ET.SubElement(c2n_root, "host")
			ET.SubElement(c2n_host, "status", state="up")
			c2n_addr = ET.SubElement(c2n_host, "address", addr=host)
			c2n_addr.set("addrtype", data[host][0])
			c2n_ports = ET.SubElement(c2n_host, "ports")
			#setting port protocol and port
			for ports in data[host]:
				if isinstance(ports, list):
					c2n_port = ET.SubElement(c2n_ports, "port", protocol=ports[0], portid=ports[1])
					ET.SubElement(c2n_port, "state", state=ports[2])
	c2n_rs = ET.SubElement(c2n_root, "runstats")
	ET.SubElement(c2n_rs, "finished", time=data['end'])
	#indenting xml
	ET.indent(c2n_root)
	xml_out=ET.ElementTree(c2n_root)
	#writing xml
	xml_out.write("converted_masscan.xml",encoding='utf-8', xml_declaration=True)


def main():
    try:
        print("converting file: %s" % sys.argv[1])
    except:
        print("usage: %s <masscan XML>" % sys.argv[0])
        print("example: %s ./masscan.xml" % sys.argv[0])
        print('output file automatically generated')
        exit()

    convert2nmap(read_masscan(sys.argv[1]))


if __name__ == "__main__":
    main()