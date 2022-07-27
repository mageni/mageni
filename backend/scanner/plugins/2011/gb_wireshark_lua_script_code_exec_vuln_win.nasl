###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_lua_script_code_exec_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Wireshark Lua Script File Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802249");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_bugtraq_id(49528);
  script_cve_id("CVE-2011-3360");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Wireshark Lua Script File Arbitrary Code Execution Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2011-15.html");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6136");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute arbitrary Lua
  script in the context of the affected application.");
  script_tag(name:"affected", value:"Wireshark versions 1.4.x before 1.4.9 and 1.6.x before 1.6.2.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error related to Lua scripts, which
  allows local users to gain privileges via a Trojan horse Lua script in an
  unspecified directory.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.9, 1.6.2 or later.");
  script_tag(name:"summary", value:"This host is installed with Wireshark and is prone to code
  execution vulnerability.");
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

if(version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.1") ||
   version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.8")) {
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
