###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_xss_vuln01_july16.nasl 11938 2018-10-17 10:08:39Z asteins $
#
# TYPO3 'mso/idna-convert' Library Cross Site Scripting Vulnerability July16
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808273");
  script_version("$Revision: 11938 $");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-17 12:08:39 +0200 (Wed, 17 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-27 10:28:48 +0530 (Wed, 27 Jul 2016)");
  script_name("TYPO3 'mso/idna-convert' Library Cross Site Scripting Vulnerability July16");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to a cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user supplied input by mso/idna-convert library.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary script code in a user's browser session.");

  script_tag(name:"affected", value:"TYPO3 versions 7.6.0 to 7.6.9 and 8.0.0 to 8.2.0");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 7.6.10 or 8.2.1
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2016-020");

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

if(typoVer =~ "7\.6")
{
  if(version_in_range(version:typoVer, test_version:"7.6.0", test_version2:"7.6.9"))
  {
    fix = "7.6.10";
    VULN = TRUE;
  }
}

else if(typoVer =~ "^8\.")
{
  if(version_in_range(version:typoVer, test_version:"8.0", test_version2:"8.2.0"))
  {
    fix = "8.2.1";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:typoVer, fixed_version:fix);
  security_message(port:typoPort, data:report);
  exit(0);
}
exit(99);
