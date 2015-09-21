# BotBlocks

This is a Microsoft Windows Application,the purpose of this tool is to detect the botnet,normally when you have infected with a malware etc..they create a connection back to their command and control server, this tool will monitor the tcp traffic of your machine and it will let you know if you are knowingly or unknowingly contacting a malicious IP address, the tool will made this decision based on the database attached to it(I have collected these malicious IP address through various internet sources and from my personal exepreince, so there can be false positives but users can edit and update this db by using a sqlite db browser),as soon as the tool detect a malicious traffic it will pop up a window so user has a choice to either block it or whitelist it, if user choose block it will terminate the existing connection and create windows firewall rule to block ,if user choose whitelist it will ignore further communication to this IP address.

I have created a windows installer for this,installation steps are basic,once the tool has installed you can find the exe short cut in the desktop. The tool will automatically start during the startup.Please read "procedure" for further details.

This is a free tool,its created for information security awareness. Big thanks to Microsoft MSDN for helping me to build Windows Application, and various internet resources for helping me to collect some malicious IP address.

Thanks
Sreejith




