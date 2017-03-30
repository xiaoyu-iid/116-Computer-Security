Scapy Lab
By: Xiaoyu Shi
Date: Oct.24, 2016

Identify what aspects of the work have been correctly implemented and what have not.

	I believe that the alarm has been correctly implemented, and several of its features 
	(Fin/Null/Xmas scans, Shellshock, etc.) has gone through robust tests. However several 
	other features still await further testing, which, as a matter of fact, makes me unconfident
	about the functionality of the alarm.

Identify anyone with whom you have collaborated or discussed the assignment.
	
	None. I have received great help from some Piazza posts and several test pcaps on Piazza.

Say approximately how many hours you have spent completing the assignment.
	
	Approximately 15, most of the time on understanding how layers work and how to actually use scapy.

Follow-up Questions:

Are the heuristics used in this assignment to determine incidents "even that good"?
	
	It is somewhat functional, yet still primitive. For examples, a lot many scans are determined via
	keywords (such as 'nmap' and 'masscan'), which is not accurate as the hacker might hide these keywords,
	or the keywords could appear in regular payloads that do not associate with scans.

	Also, the coverage of scans that can be detected is too narrow. For example, the alarm cannot detect 
	most of the nmap scans (as there are, like 13, of them?), and it cannot identify most of the SYN scans.

If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
	
	First of all, I would focus on the accuracy of the available scans in the alarm. For example, the regular 
	payloads that happen to include certain scan keywords could be ruled out.

	Second of all, I could expand the number of scans that could be detected by the alarm.

	Third of all, I think it could be useful for the alarm to inspect on suspicious GET requests. For example, 
	the alarm could detect if the website visited is downloading malware to the user's devices.