###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_win_jul12.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Wireshark Multiple Denial of Service Vulnerabilities - July 12 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802907");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-2392", "CVE-2012-2393", "CVE-2012-3825", "CVE-2012-3826");
  script_bugtraq_id(53651, 53652);
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-05 13:52:34 +0530 (Thu, 05 Jul 2012)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities - July 12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49226/");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-08.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2012-09.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=7138");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.13 and 1.6.x before 1.6.8 on Windows");
  script_tag(name:"insight", value:"- Errors in the ANSI MAP, ASF, BACapp, Bluetooth HCI, IEEE 802.11,
    IEEE 802.3, LTP, and R3 dissectors can be exploited to cause infinite loops
    via specially crafted packets.

  - An error in the DIAMETER dissector does not properly allocate memory and
    can be exploited to cause a crash via a specially crafted packet.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.13, 1.6.8 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.12") ||
   version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.7")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

exit(99);
