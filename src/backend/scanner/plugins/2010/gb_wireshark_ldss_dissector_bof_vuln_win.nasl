###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_ldss_dissector_bof_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Wireshark LDSS Dissector Buffer Overflow Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801555");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-4300");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Wireshark LDSS Dissector Buffer Overflow Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42290");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/3038");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-14.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the application.");
  script_tag(name:"affected", value:"Wireshark version 1.2.0 to 1.2.12 and 1.4.0 to 1.4.1");
  script_tag(name:"insight", value:"The flaw is due to heap-based buffer overflow in
  'dissect_ldss_transfer()' function (epan/dissectors/packet-ldss.c) in the
  LDSS dissector, which allows attackers to cause a denial of service (crash)
  and possibly execute arbitrary code via an LDSS packet with a long digest
  line.");
  script_tag(name:"solution", value:"Upgrade to Wireshark 1.4.2 or 1.2.13 later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

if(version_in_range(version:sharkVer, test_version:"1.4.0", test_version2:"1.4.1") ||
   version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.12")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
