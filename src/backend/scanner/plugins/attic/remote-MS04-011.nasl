###############################################################################
# OpenVAS Vulnerability Test
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
# Microsoft Windows NT� Workstation 4.0 Service Pack 6a
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
# Bulletin ID    Windows NT 4.0         Windows 2000     Windows XP             Windows Server 2003
# MS99-023       Replaced               Not Applicable   Not Applicable         Not Applicable
# MS00-027       Not Replaced           Replaced         Not Applicable         Not Applicable
# MS00-032       Not Applicable         Replaced         Not Applicable         Not Applicable
# MS00-070       Not Replaced           Replaced         Not Applicable         Not Applicable
# MS02-050       Replaced               Not Replaced     Not Replaced           Not Applicable
# MS02-051       Not Applicable         Replaced         Not Replaced           Not Applicable
# MS02-071       Replaced               Replaced         Not Replaced           Not Applicable
# MS03-007       Not Replaced           Replaced         Not Replaced           Not Applicable
# MS03-013       Replaced               Replaced         Not Replaced           Not Applicable
# MS03-025       Not Applicable         Replaced         Not Applicable         Not Applicable
# MS03-041       Replaced               Not Replaced     Not Replaced           Not Replaced
# MS03-045       Replaced               Replaced         Not Replaced           Not Replaced
# MS04-007       Replaced               Replaced         Replaced               Replaced
#
# Tested on:
#
# [Windows 2000]
#
# [Windows XP]
#
# [Windows 2003]

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101011");
  script_version("2020-04-02T11:36:28+0000");
  script_tag(name:"last_modification", value:"2020-04-03 10:09:42 +0000 (Fri, 03 Apr 2020)");
  script_tag(name:"creation_date", value:"2009-03-15 22:32:35 +0100 (Sun, 15 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2003-0533", "CVE-2003-0663", "CVE-2003-0719", "CVE-2003-0806", "CVE-2003-0906", "CVE-2003-0907", "CVE-2003-0908",
                "CVE-2003-0909", "CVE-2003-0910", "CVE-2004-0117", "CVE-2004-0118", "CVE-2004-0119", "CVE-2004-0120", "CVE-2004-0123");
  script_name("MS04-011 security check");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");

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
