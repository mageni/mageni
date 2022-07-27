###############################################################################
# OpenVAS Vulnerability Test
#
# Wireshark Daintree SNA File Parser Denial of Service Vulnerability (Linux)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900989");
  script_version("2019-04-29T15:08:03+0000");
  script_tag(name:"last_modification", value:"2019-04-29 15:08:03 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2009-12-24 14:01:59 +0100 (Thu, 24 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4376");
  script_bugtraq_id(37407);
  script_name("Wireshark Daintree SNA File Parser Denial of Service Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37842");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3596");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2009-09.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=4294");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_lin.nasl");
  script_mandatory_keys("Wireshark/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause Denial of service
  condition by tricking the user into opening a malformed packet trace file
  through Wireshark.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.4 on Linux.");
  script_tag(name:"insight", value:"A boundary error occurs in the 'daintree_sna_read()' function in the Daintree
  SNA file parser while processing malformed captured pcap files.");
  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.2.5.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to Denial of
  Service vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Linux/Ver");
if(!sharkVer)
  exit(0);

if(version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
