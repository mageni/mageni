###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_sep10.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Apple Safari Multiple Vulnerabilities - Sep10
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
  script_oid("1.3.6.1.4.1.25623.1.0.801514");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-1805", "CVE-2010-1806", "CVE-2010-1807");
  script_bugtraq_id(43049, 43048, 43047);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Apple Safari Multiple Vulnerabilities - Sep10");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT4333");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2010//Sep/msg00001.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_mandatory_keys("AppleSafari/Version");
  script_tag(name:"impact", value:"Successful exploitation allow attackers to execute arbitrary code or can
  even crash the browser.");
  script_tag(name:"affected", value:"Apple Safari 5.x before 5.0.2 on Windows");
  script_tag(name:"insight", value:"The flaws are due to

  - An use-after-free vulnerability in the application, which allows remote
    attackers to execute arbitrary code via 'run-in' styling in an element,
    related to object pointers.

  - An untrusted search path vulnerability on Windows allows local users
    to gain privileges via a Trojan horse 'explorer.exe'.

  - An error exists in the handling of 'WebKit', which does not properly
    validate floating-point data, which allows remote attackers to execute
    arbitrary cod via a crafted HTML document.");
  script_tag(name:"solution", value:"Upgrade Apple Safari 5.0.2 or later.");
  script_tag(name:"summary", value:"The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.apple.com/support/downloads/");
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

if(version_in_range(version:safVer, test_version:"5.0", test_version2:"5.33.18.4")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
