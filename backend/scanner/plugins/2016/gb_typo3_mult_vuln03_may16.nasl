###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln03_may16.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# TYPO3 Multiple Vulnerabilities-03 May16
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807826");
  script_version("$Revision: 12455 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-20 17:17:16 +0530 (Fri, 20 May 2016)");
  script_name("TYPO3 Multiple Vulnerabilities-03 May16");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in some backend components which fail to properly encode user input.

  - An error in the default authentication service which misses to invalidate
    empty strings as password.

  - The workspace/version preview link created by a privileged (backend) user
    could be abused to obtain certain editing permission.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct authentication bypass, XSS and privilege escalation
  attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.x before 6.2.20, 7.6.x
  before 7.6.5 and 8.0.0");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.20 or 7.6.5
  or 8.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-012");
  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-011");
  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-009");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://typo3.org/typo3-cms");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!typoVer = get_app_version(cpe:CPE, port:typoPort)){
  exit(0);
}

if(typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+") exit(0); # Version is not exact enough

if(typoVer =~ "6\.2")
{
  if(version_in_range(version:typoVer, test_version:"6.2.0", test_version2:"6.2.19"))
  {
    fix = "6.2.20";
    VULN = TRUE;
  }
}

else if(typoVer =~ "7\.6")
{
  if(version_in_range(version:typoVer, test_version:"7.6.0", test_version2:"7.6.4"))
  {
    fix = "7.6.5";
    VULN = TRUE;
  }
}

else if(version_is_equal(version:typoVer, test_version:"8.0.0"))
{
  fix = "8.0.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:typoVer, fixed_version:fix);
  security_message(port:typoPort, data:report);
  exit(0);
}

exit(99);
