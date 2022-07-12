###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_jabber_info_disc_vuln_win.nasl 2015-07-03 11:19:11 +0530 Jul$
#
# Cisco Jabber Information Disclosure Vulnerability June15 (Windows)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cisco:jabber";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805712");
  script_version("$Revision: 11424 $");
  script_cve_id("CVE-2015-4218");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-07-03 11:19:11 +0530 (Fri, 03 Jul 2015)");
  script_name("Cisco Jabber Information Disclosure Vulnerability June15 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Cisco
  Jabber and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper
  validation of GET parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Cisco Jabber versions through
  9.6(3) and 9.7 through 9.7(5) Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=39494");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_jabber_detect_win.nasl");
  script_mandatory_keys("Cisco/Jabber/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!jbVer = get_app_version(cpe:CPE)){
  exit(0);
}

#Removing Build from Version
jbVer = ereg_replace(string:jbVer, pattern:".[0-9][0-9]+", replace:"");
if(!jbVer){
  exit(0);
}

if(version_in_range(version:jbVer, test_version:"9.6.0", test_version2:"9.6.3")||
   version_in_range(version:jbVer, test_version:"9.7.0", test_version2:"9.7.5"))
{
   report = 'Installed version: ' + jbVer + '\n' +
           'Fixed version:     WillNotFix \n';
   security_message(data:report);
   exit(0);
}
