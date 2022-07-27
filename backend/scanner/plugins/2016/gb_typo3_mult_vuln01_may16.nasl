###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln01_may16.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# TYPO3 Multiple Vulnerabilities-01 May16
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
  script_oid("1.3.6.1.4.1.25623.1.0.807824");
  script_version("$Revision: 14181 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-20 16:46:03 +0530 (Fri, 20 May 2016)");
  script_name("TYPO3 Multiple Vulnerabilities-01 May16");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error in the database escaping API results.

  - An error in the legacy form component which fails to sanitize content from
    editors.

  - An error in the form component which fails to sanitize content from
    unauthenticated  website visitors.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to conduct SQL injection and XSS attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 6.2.0 to 6.2.17.");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 6.2.18
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2015-016");
  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-003");
  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-004");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);

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
  if(version_in_range(version:typoVer, test_version:"6.2.0", test_version2:"6.2.17"))
  {
    report = report_fixed_ver(installed_version:typoVer, fixed_version:"6.2.18");
    security_message(port:typoPort, data:report);
    exit(0);
  }
}

exit(99);