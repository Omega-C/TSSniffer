import socket, requests, subprocess
print("modules gotten")

__author__="just a person that did this in 2 days (youtube creator https://www.youtube.com/channel/UCMADIRDf7d8pVG719yn1t4A), 16/02/2020-17/02/2020"

"""
notes:
stun for video calls and skype could be used but less used.
"""

def get_loc(jdata):
	ip=jdata["from"]
	url="https://ipinfo.io/{}/json".format(str(ip))
	data=requests.get(url,headers={"User-agent":"Chrome"}).json()
	if "bogon" in data.keys():
		return "\n\n{} is a bogon address-----------\n".format(ip)
	try:
		return "\ndata:\n\nip:'{ip}'\nto:'{{to}}'\ncountry:'{country}'\nregion:'{region}'\ncity:'{city}'\nlocation:'{loc}'\npostal:'{postal}'\nmore accurate:'https://whatismyipaddress.com/ip/{ip}'\n\n-----------".format(**data).format(**jdata)
	except Exception as e:
		return "\n{{}} ERROR,{}\n\n-----------".format(str(e)).format(ip)

def parse_command(command):
	command=command.decode("utf8").split(" ")
	while "" in command:
		command.remove("")
	if len(command)<6:
		return {"no":"","time":"","from":"","to":"","type":""}
	cmd={}
	cmd["no"]=command[0]
	cmd["time"]=command[1]
	cmd["from"]=command[2]
	cmd["to"]=command[4]
	cmd["type"]=command[5]
	return cmd

def run(flow_type,disp_filter="",cap_filter="",types=[]):
	cmd_path="/Applications/Wireshark.app/Contents/MacOS/tshark -f '{0}' -Y '{1}'".format(cap_filter,disp_filter)#use a diffrent path to get to tshark if needed
	print("command: "+cmd_path)

	process=subprocess.Popen(cmd_path,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
	print("process started")

	sock_self=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock_self.connect(("8.8.8.8",80))
	pr_ip=sock_self.getsockname()[0]
	sock_self.close()
	print("computer ip is gotten")

	if flow_type=="ipl":
		dont_read=[pr_ip,""]

	try:
		for line in iter(process.stdout.readline,b""):
			command_parsed=parse_command(line)
			if flow_type=="srf":
				print(line.decode("utf8"))

			if flow_type=="ipl":
				if command_parsed["from"] not in dont_read and command_parsed["type"] in types:
					loc_data=get_loc(command_parsed)
					print(loc_data)
					dont_read+=[command_parsed["from"]]

	except KeyboardInterrupt:
		process.kill()
		print("\nProcess killed")
		return None
	return None

def main():
	flow_types=["ipl","srf"]
	flow="ipl"
	while flow not in flow_types:
		flow=str(input("type of flow ({}): ".format(",".join(flow_types))))

	disp_filter=""
	cap_filter=""
	types=["STUN"]

	run(flow,disp_filter=disp_filter,cap_filter=cap_filter,types=types)
	print("packet tracing over")

if __name__=="__main__":
	main()
