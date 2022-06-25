###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln01_jan15.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# TYPO3 Multiple Vulnerabilities-01 Jan-2015 (SA-2014-003)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805247");
  script_version("$Revision: 11872 $");
  script_cve_id("CVE-2014-9508", "CVE-2014-9509");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-01-19 12:19:42 +0530 (Mon, 19 Jan 2015)");
  script_name("TYPO3 Multiple Vulnerabilities-01 Jan-2015 (SA-2014-003)");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Certain input passed to the homepage is not properly sanitised before being
    used to generate anchor links.

  - An error related to the 'config.prefixLocalAnchors' configuration option.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to poison the cache and conduct spoofing attacks.");

  script_tag(name:"affected", value:"TYPO3 versions 4.5.x before 4.5.39, 4.6.x
  through 6.2.x before 6.2.9, and 7.x before 7.0.2");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.5.39 or 6.2.9
  or 7.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60371");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-core-sa-2014-003");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough

if(version_in_range(version:typoVer, test_version:"4.5.0", test_version2:"4.5.38") ||
   version_in_range(version:typoVer, test_version:"4.6.0", test_version2:"6.2.8") ||
   version_in_range(version:typoVer, test_version:"7.0.0", test_version2:"7.0.1"))
{
  report = report_fixed_ver(installed_version:typoVer, fixed_version:"4.5.39/6.2.9/7.0.2");
  security_message(port:typoPort, data:report);
  exit(0);
}

exit(99);