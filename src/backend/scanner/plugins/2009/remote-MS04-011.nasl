###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS04-011.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Microsoft Security Bulletin MS04-011
# http://www.microsoft.com/technet/security/bulletin/ms04-011.mspx
#
# LSASS Remote Code Execution Vulnerability - CAN-2003-0533
# LDAP Denial Of Service Vulnerability - CAN-2003-0663
# PCT  Remote Code Execution Vulnerability - CAN-2003-0719
# Winlogon  Remote Code Execution Vulnerability - CAN-2003-0806
# Metafile  Remote Code Execution Vulnerability - CAN-2003-0906
# Help and Support Center  Remote Code Execution Vulnerability - CAN-2003-0907
# Utility Manager  Privilege Elevation Vulnerability - CAN-2003-0908
# Local Descriptor Table  Privilege Elevation Vulnerability - CAN-2003-0910
# H.323  Remote Code Execution Vulnerability - CAN-2004-0117
# Virtual DOS Machine  Privilege Elevation Vulnerability - CAN-2004-0118
# Negotiate SSP  Remote Code Execution Vulnerability - CAN-2004-0119
# SSL  Denial Of Service Vulnerability - CAN-2004-0120
# ASN.1 Double Free Vulnerability - CAN-2004-0123
#
# Affected Software:
# Microsoft Windows NT® Workstation 4.0 Service Pack 6a
# Microsoft Windows NT Server 4.0 Service Pack 6a
# Microsoft Windows NT Server 4.0 Terminal Server Edition Service Pack 6
# Microsoft Windows 2000 Service Pack 2, Microsoft Windows 2000 Service Pack 3, and Microsoft Windows 2000 Service Pack 4
# Microsoft Windows XP and Microsoft Windows XP Service Pack 1
# Microsoft Windows XP 64-Bit Edition Service Pack 1
# Microsoft Windows XP 64-Bit Edition Version 2003
# Microsoft Windows Server 2003
# Microsoft Windows Server 2003 64-Bit Edition
# Microsoft NetMeeting
# Microsoft Windows 98, Microsoft Windows 98 Second Edition (SE), and Microsoft Windows Millennium Edition (ME)
#
# remote-MS04-011.nasl
#
# Note:
# This security update replaces several prior security bulletins.
# The security bulletin IDs and operating systems that are affected are listed in the table below.
#
# Bulletin ID	 Windows NT 4.0 	Windows 2000	 Windows XP 		Windows Server 2003
# MS99-023	 Replaced		Not Applicable	 Not Applicable 	Not Applicable
# MS00-027 	 Not Replaced		Replaced	 Not Applicable		Not Applicable
# MS00-032	 Not Applicable		Replaced	 Not Applicable		Not Applicable
# MS00-070	 Not Replaced		Replaced	 Not Applicable 	Not Applicable
# MS02-050	 Replaced		Not Replaced	 Not Replaced		Not Applicable
# MS02-051	 Not Applicable		Replaced	 Not Replaced		Not Applicable
# MS02-071	 Replaced		Replaced	 Not Replaced		Not Applicable
# MS03-007	 Not Replaced		Replaced	 Not Replaced		Not Applicable
# MS03-013	 Replaced		Replaced	 Not Replaced		Not Applicable
# MS03-025	 Not Applicable		Replaced	 Not Applicable 	Not Applicable
# MS03-041	 Replaced		Not Replaced	 Not Replaced		Not Replaced
# MS03-045	 Replaced		Replaced	 Not Replaced		Not Replaced
# MS04-007	 Replaced		Replaced	 Replaced		Replaced
#
# Tested on:
#
# [Windows 2000]
#
# [Windows XP]
#
# [Windows 2003]
#
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101011");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-03-15 22:32:35 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2003-0533", "CVE-2003-0663", "CVE-2003-0719", "CVE-2003-0806", "CVE-2003-0906", "CVE-2003-0907", "CVE-2003-0908",
                "CVE-2003-0909", "CVE-2003-0910", "CVE-2004-0117", "CVE-2004-0118", "CVE-2004-0119", "CVE-2004-0120", "CVE-2004-0123");
  script_name("MS04-011 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("os_detection.nasl");
  script_mandatory_keys("Host/runs_windows");

  script_tag(name:"solution", value:"Microsoft has released a patch to fix these issues.");

  script_tag(name:"summary", value:"Windows operating system are affected to multiple remote code
  execution and privileges escalation vulnerabilities.");

  script_tag(name:"impact", value:"An attacker who successfully exploited the most severe of these vulnerabilities could take
  complete control of an affected system, including:

  - installing programs

  - viewing, changing, or deleting data

  - creating new accounts that have full privileges.");

  script_tag(name:"insight", value:"These vulnerabilities includes:

  LSASS Remote Code Execution Vulnerability - CAN-2003-0533

  LDAP Denial Of Service Vulnerability - CAN-2003-0663

  PCT Remote Code Execution Vulnerability - CAN-2003-0719

  Winlogon Remote Code Execution Vulnerability - CAN-2003-0806

  Metafile Remote Code Execution Vulnerability - CAN-2003-0906

  Help and Support Center Remote Code Execution Vulnerability - CAN-2003-0907

  Utility Manager Privilege Elevation Vulnerability - CAN-2003-0908

  Windows Management Privilege Elevation Vulnerability - CAN-2003-0909

  Local Descriptor Table Privilege Elevation Vulnerability - CAN-2003-0910

  H.323 Remote Code Execution Vulnerability - CAN-2004-0117

  Virtual DOS Machine Privilege Elevation Vulnerability - CAN-2004-0118

  Negotiate SSP Remote Code Execution Vulnerability - CAN-2004-0119

  SSL Denial Of Service Vulnerability - CAN-2004-0120

  ASN.1 Double Free Vulnerability - CAN-2004-0123.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66); ## This NVT is deprecated as it seems to be broken

# global socket shared by all functions
global_var sk;

# Test the remote host for available connection
function RemoteConnect(prt)
{

	sk = open_sock_tcp(prt);
	if(sk)
		return TRUE;
	else
		close(sk);
		return FALSE;
}

# Close the remote connection
function RemoteClose()
{
	close(sk);
}


function RemoteExploit(Tcnx, Treq, Tresp, Tport)
{
	Tcnx = RemoteConnect(prt:Tport);
	if(!Tcnx)
		return FALSE;
	else
		send(socket:sk, data:Treq);
		response = recv(socket:sk, length:8192);

		if(Tresp >< response)
			return TRUE;
		else
			return FALSE;
}


#
# NVT Exploit code stars here
#

netbios_ssn = get_kb_item("Services/tcp/ports/445");
microsoft_ds = get_kb_item("Services/tcp/ports/139");

if(microsoft_ds)
{
	vulnerable = TRUE;

	# connect to the remote host
	conn = RemoteConnect(prt:microsoft_ds);
	if(!conn)
		RemoteClose();
	else
		# build the malicious request
            	request_0 = raw_string("\x00\x00\x00\x2F\xFF\x53\x4D\x42\x72\x00\x00\x00\x00\x18",
                         	 "\x01\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                         	 "\xFF\xFF\x12\x34\x00\x00\xAB\xCD\x00\x0C\x00\x02\x4E\x54",
                         	 "\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00");

            	reply_0 = "SMBr\x00\x00\x00\x00";

            	request_1 = raw_string("\x00\x00\x00\x5f\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x08",
                          	"\x01\xC8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                          	"\x00\x00\x00\x00\x00\x00\xAB\xCD\x0C\xFF\x00\x00\x00\x01",
                          	"\x40\x02\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00",
                          	"\x00\x5C\x00\x00\x80\x24\x00\x60\x0B\x06\x00\x00\x00\x00",
                          	"\x00\x30\x00\x00\x00\x00\x00\x00\x00\x19\x00\x02\x00\x4E",
                          	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x02\x00\x00",
                          	"\x00");

            	reply_1 = "SMBs\x16\x00\x00\xC0";

		# test the microsoft-ds service for vulnerability
		if(!RemoteExploit(Tcnx:conn, Treq:request_0, Tresp:reply_0, Tport:microsoft_ds));
			vulnerable = FALSE;
			if(!RemoteExploit(Tcnx:conn, Treq:request_1, Tresp:reply_1, Tport:microsoft_ds));
			vulnerable = FALSE;
		RemoteClose();

	if(vulnerable == TRUE)
		security_message(port:microsoft_ds);
}

if(netbios_ssn)
{
	vulnerable = TRUE;

	# connect to the remote host
	conn = RemoteConnect(prt:netbios_ssn);
	if(!conn)
		RemoteClose();
	else
		# build the malicious request
		request_2 = raw_string("\x81\x00\x00\x44\x20\x43\x4b\x46\x44\x45\x4e\x45\x43\x46",
                          "\x44\x45\x46\x46\x43\x46\x47\x45\x46\x46\x43\x43\x41\x43",
                          "\x41\x43\x41\x43\x41\x43\x41\x43\x41\x00\x20\x45\x4a\x46",
                          "\x41\x45\x4d\x45\x46\x45\x48\x45\x4a\x45\x50\x45\x4f\x43",
                          "\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x43\x41\x41",
                          "\x41\x00");

            	reply_2 = "\x82\x00\x00\x00";

            	request_3 = raw_string("\x00\x00\x00\x2F\xFF\x53\x4D\x42\x72\x00\x00\x00\x00\x18",
                          "\x01\x48\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                          "\xFF\xFF\x12\x36\x00\x00\xAB\xCF\x00\x0C\x00\x02\x4E\x54",
                          "\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00");

            	reply_3 = "SMBr\x00\x00\x00\x00";

            	request_4 = raw_string("\x00\x00\x00\x5f\xFF\x53\x4D\x42\x73\x00\x00\x00\x00\x08",
                          "\x01\xC8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                          "\x00\x00\x00\x00\x00\x00\xAB\xCF\x0C\xFF\x00\x00\x00\x01",
                          "\x40\x02\x00\x01\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00",
                          "\x00\x5C\x00\x00\x80\x24\x00\x60\x0B\x06\x00\x00\x00\x00",
                          "\x00\x30\x00\x00\x00\x00\x00\x00\x00\x19\x00\x02\x00\x4E",
                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x19\x00\x02\x00\x00",
                          "\x00");

            	reply_4 = "SMBs\x16\x00\x00\xC0";

		# test the netbios-ssn service for vulnerability
		if(!RemoteExploit(Tcnx:conn, Treq:request_2, Tresp:reply_2, Tport:netbios_ssn));
			vulnerable = FALSE;
			if(!RemoteExploit(Tcnx:conn, Treq:request_3, Tresp:reply_3, Tport:netbios_ssn));
			vulnerable = FALSE;
			if(!RemoteExploit(Tcnx:conn, Treq:request_4, Tresp:reply_4, Tport:netbios_ssn));
			vulnerable = FALSE;

		RemoteClose();

	if(vulnerable == TRUE)
		security_message(port:netbios_ssn);
}

