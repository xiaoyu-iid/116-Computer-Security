README.md
Technical Risk Analysis - Comparison between my analysis & Veracode report
Xiaoyu Shi
Nov. 21, 2016


Differences:

	1. The overarching difference between my evaluation and Veracode report is that Veracode is able to identify most of (if not all) existing risks under one category (for example, all risks that belong to "Code Injection"), while my evaluation was only able to identify the exploitable features that emerged in the CTF, and in my analysis. Some of the major differences are as followed:

		a. In analyzing PHP injections, Veracode identified a "Improper Control of Filename for Include/Require Statement in PHP Program ('PHP Remote File Inclusion') CWE ID 98" that I did not find out. 

		b. In Credential Management, I did not find the "Hardcoded Password" risk.

		c. In Cryptography, I identified the problems to be unsalted hashes and use of risky cryptographic algorithms; I did not find Insufficient Entrophy or missing encryptions in /filesystem.

		d. I identified the Directory Traversal risk to be unauthorized access to directories and files; the risk should be External Control of File Name or Path.

	2. There are also risks that I did not identify:

		a. Encapsulation (Deserialization of Untrusted Data, CWE ID 502)

		b. Code Quality (Improper Resource Shutdown or Release, CWE ID 404)

		c. Untrusted Initializations (External Initialization of Trusted Variables or Data Stores, CWE ID 454)

	3. Veracode was also able to identify the locations that need to be mitigated.


Similarities:

	1. My evaluation and Veracode reports both noticed the riskiest issues - PHP injections (I specified them to be Eval injections) and SQL injections

	2. We both identified the risk of Credential Management, Cross-site Scripting, Cryptographic Issues, and Directory Traversal.


Features I hope Veracode could provide:


