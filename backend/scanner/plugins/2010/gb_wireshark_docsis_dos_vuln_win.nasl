###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_docsis_dos_vuln_win.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Wireshark DOCSIS Dissector Denial of Service Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801208");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_bugtraq_id(39950);
  script_cve_id("CVE-2010-1455");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark DOCSIS Dissector Denial of Service Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39661");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-03.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2010-04.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to crash the application.");
  script_tag(name:"affected", value:"Wireshark Version 0.9.6 through 1.0.12 and
  Wireshark Version 1.2.0 through 1.2.7");
  script_tag(name:"insight", value:"The flaw is caused by an error in the DOCSIS (Data Over Cable Service
  Interface Specification) dissector when processing malformed data. An
  attacker can exploit this vulnerability by tricking a user into opening
  a malformed packet trace file.");
  script_tag(name:"solution", value:"Upgrade to the latest version of Wireshark 1.2.8 or 1.0.13.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to
  denial of service vulnerability.");
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

if(version_in_range(version:sharkVer, test_version:"0.9.6",
   test_version2:"1.0.12") || version_in_range(version:sharkVer,
   test_version:"1.2.0", test_version2:"1.2.7")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

