###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_jun13_win.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Wireshark Multiple DoS Vulnerabilities - June 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803652");
  script_version("$Revision: 11865 $");
  script_cve_id("CVE-2013-4081", "CVE-2013-4074");
  script_bugtraq_id(60505, 60500);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-28 13:30:52 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple DoS Vulnerabilities - June 13 (Windows)");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1028648");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause denial of
  service via a crafted packet.");
  script_tag(name:"affected", value:"Wireshark 1.6.x before 1.6.16, 1.8.x before 1.8.8 on Windows");
  script_tag(name:"insight", value:"- 'http_payload_subdissector' function in epan/dissectors/packet-http.c in
     HTTP dissector does not determine when to use a recursive approach.

  - 'dissect_capwap_data' function in epan/dissectors/packet-capwap.c in CAPWAP
    dissector incorrectly uses a -1 data value to represent an error condition.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.6.16 or 1.8.8 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.wireshark.org/download");
  exit(0);
}


include("version_func.inc");

sharkVer = get_kb_item("Wireshark/Win/Ver");

if(sharkVer && sharkVer=~ "^(1.6|1.8)")
{
  if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.15")||
     version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.7"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
