###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_mult_vuln_oct_10.nasl 2014-01-09 15:25:39Z jan$
#
# TYPO3 Multiple Vulnerabilities Oct10
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.804219");
  script_version("$Revision: 14117 $");
  script_cve_id("CVE-2010-3714", "CVE-2010-3715", "CVE-2010-3716",
                "CVE-2010-3717", "CVE-2010-4068");
  script_bugtraq_id(43786);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-09 15:25:39 +0530 (Thu, 09 Jan 2014)");
  script_name("TYPO3 Multiple Vulnerabilities Oct10");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to get sensitive
  information or cause DoS condition.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple error exists in the application,

  - An error exist in class.tslib_fe.php script, which does not properly compare
  certain hash values during access-control decisions.

  - An error exist backend and sys_action task, which fails to validate certain
  user provided input properly.

  - An error exist in Filtering API, which fails to handle large strings.");

  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.2.15, 4.3.7, 4.4.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to multiple vulnerabilities.");
  script_tag(name:"affected", value:"TYPO3 version 4.2.14 and below, 4.3.6 and below, 4.4.3 and below");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41691");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-020/");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

if(typoVer = get_app_version(cpe:CPE, port:typoPort))
{
  if( typoVer !~ "[0-9]+\.[0-9]+\.[0-9]+" ) exit( 0 ); # Version is not exact enough
  if(version_in_range(version:typoVer, test_version:"4.2.0", test_version2:"4.2.14") ||
     version_in_range(version:typoVer, test_version:"4.3.0", test_version2:"4.3.6") ||
     version_in_range(version:typoVer, test_version:"4.4.0", test_version2:"4.4.3"))
  {
    security_message(typoPort);
    exit(0);
  }
}
