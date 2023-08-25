# WazuhSiem
Full on tutorial on how to setup Wazuh Open Source SIEM w/ ways to make the most out of it
Import and access the virtual machine

1.Import the OVA to the virtualization platform.

2. If you're using VirtualBox, set the VMSVGA graphic controller. Setting another graphic controller freezes the VM window.

	a.Select the imported VM.

	b. Click Settings > Display

	C. In Graphic Controller, select <VMSGA option>


3. start the machine
	
Verify ip with "ip r" 
	Machine IP = 192.168.0.33

4. Access the virtual machine using the following user and password. You can use the virtualization platform or access it via SSH.

User: wazuh-user
password: wazuh

SSH root user login has been deactivated; nevertheless, the wazuh-user retains sudo privileges. Root privilege escalation can be achieved by executing the following command:
		sudo -i 


Access the Wazuh dashboard
Shortly after starting the VM, the Wazuh dashboard can be accessed from the web interface by using the following credentials:


URL: https://<wazuh_server_ip>
user: admin
password: admin

				Configuration files

All components included in this virtual image are configured to work out-of-the-box, without the need to modify any settings. However, all components can be fully customized. These are the configuration files locations:

Wazuh manager: /var/ossec/etc/ossec.conf

Wazuh indexer: /etc/wazuh-indexer/opensearch.yml

Filebeat-OSS: /etc/filebeat/filebeat.yml

Wazuh dashboard:

/etc/wazuh-dashboard/opensearch_dashboards.yml

/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml


				PERSONAL SETUP 
Win 11 IP : 192.168.0.174
Wazuh Server IP :192.168.0.224
 
1. Command to get Agent on the target Computer (need powershell 3.0)
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.5.1-1.msi -OutFile ${env:tmp}\wazuh-agent.msi; msiexec.exe /i ${env:tmp}\wazuh-agent.msi /q WAZUH_MANAGER='192.168.0.224' WAZUH_REGISTRATION_SERVER='192.168.0.224' WAZUH_AGENT_GROUP='WindowsPCs' WAZUH_AGENT_NAME='Win11_Home' 

2. Start the agent with NET START Wazuh 

	Will give details about 
	1. MITRE Framework on systems/servers
	2. Compliance for HIPPA/GDPR/NIST
	3. Security Config assessment/ how to fix

	Why the Security Config assessment is powerful

1. Will give you passed / failed list
2. You can click into them to get more info 
	It will give you info on 
	Rationale : Why they are telling you this 
	Remedation : How to fix the problem 
	Description : What the problem is in a readable form
	Checks : Ways to check if you fixed the problem 
	Mitre : Shows all of the possible Mitre techniques that could be used 

				Agent Dashboard 
1. Shows authentication Failures (possible brute force attacks)
2. PIE CHART of the Top 5 Alerts 
3. List of Security Alerts 

				Vulnerabilities 
1. Not enabled on default 
2. How to set it up : 
	


		How to turn on Real Time File Monitoring (Windows) 
1. Go to Windows Explorer 
2. Locate C drive 
3. Go into Program Files (x86)
4. Click into the filename "ossec-agent" 
5. Locate "ossec.conf" and edit the file with notepad
6. Do cntrl + f and search "syscheck" this will bring you to the "File Integrity monitoring" section 
7. Anywhere in the directories option will be where you can add in your line
8. Add in: <directories realtime= "yes" report_changes="yes" check_all="yes">C:\Users\domin\Desktop\Wazuh SIEM</directories>
9. Restart the service by doing restart-service -name wazuh 
	
	The file can be any file you want to monitor (Just have to include full directory path)


		How to turn Monitor Registry Keys/ Change Time interval

Standard time for RegEdit to scan is 12 hours

1. 1. Go to Windows Explorer 
2. Locate C drive 
3. Go into Program Files (x86)
4. Click into the filename "ossec-agent" 
5. Locate "ossec.conf" and edit the file with notepad
6. Under syscheck, you will scroll down untill you see "Windows Registry entries to monitor"
7. Add in <windows_registry>HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WazuhReg</windows_registry>
	Keep in mind this is mine, any regedit you want to do is what you would input

8. Find "Frequency that syscheck is executed" and change the number to whatever you want (I did 60.. one minute)
9. Restart Wazuh using "restart-service -name wazuh 
10. Verify the Key was added and modify it to view the results in "Events" 
