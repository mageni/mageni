##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_mult_vuln_sept08_win_900212.nasl 12602 2018-11-30 14:36:58Z cfischer $
# Description: Wireshark Multiple Vulnerabilities - Sept-08 (Windows)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900212");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
  script_bugtraq_id(31009);
  script_cve_id("CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_family("Denial of Service");
  script_name("Wireshark Multiple Vulnerabilities - Sept-08 (Windows)");
  script_tag(name:"summary", value:"Check for vulnerable version of Wireshark/Ethereal");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31674");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2493");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-05.html");

  script_tag(name:"affected", value:"Wireshark versions 1.0.2 and prior on Windows (All).");

  script_tag(name:"solution", value:"Upgrade to wireshark 1.0.3 or later.");

  script_tag(name:"impact", value:"Successful exploitation could result in denial of service
  condition or application crash by injecting a series of malformed
  packets or by convincing the victim to read a malformed packet.");

  exit(0);
}

 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 report = string("\n Overview : The host is running Wireshark/Ethereal, which" +
		 "is prone to multiple\n vulnerabilities.\n" +
		 "\n        Vulnerability Insight:\n" +
		 "\n        Flaw(s) is/are due to,\n");
 vuln1 = string("       - infinite loop errors in the NCP dissector.\n");
 vuln2 = string("       - an error when uncompressing zlib-compressed packet data.\n");
 vuln3 = string("       - an error when reading a Tektronix .rf5 file.\n");

 etherealVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
			       "\Uninstall\Ethereal", item:"DisplayVersion");
 if(etherealVer)
 {
	etherealVer = ereg_replace(pattern:"Ethereal (.*)", replace:"\1",
                            	   string:etherealVer);
	if(ereg(pattern:"^0\.(9\.[7-9]|10\.(0?[0-9]|1[0-3]))$",
		string:etherealVer))
	{
		security_message(data:string(report, vuln1));
		exit(0);
	}
	else if(ereg(pattern:"^0\.(10\.14|99\.0)$",
		     string:etherealVer))
	{
		security_message(data:string(report, vuln1, vuln2));
                exit(0);
        }
 }

 wiresharkVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"+
			        "\Uninstall\Wireshark", item:"DisplayVersion");
 if(!wiresharkVer){
	exit(0);
 }

 if(ereg(pattern:"^0\.99\.[1-5]$", string:wiresharkVer))
 {
	security_message(data:string(report, vuln1, vuln2));
	exit(0);
 }
 else if(ereg(pattern:"^(0\.99\.[6-9]|1\.0\.[0-2])$", string:wiresharkVer)){
	security_message(data:string(report, vuln1, vuln2, vuln3));
 }
