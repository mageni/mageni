###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_vuln01_june15.nasl 2015-06-04 17:24:38 +0530 Jun$
#
# phpMyAdmin Multiple Vulnerabilities -01 June15
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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805398");
  script_version("$Revision: 11975 $");
  script_cve_id("CVE-2015-3902", "CVE-2015-3903");
  script_bugtraq_id(74660, 74657);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 08:54:12 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-06-04 17:24:38 +0530 (Thu, 04 Jun 2015)");
  script_name("phpMyAdmin Multiple Vulnerabilities -01 June15");

  script_tag(name:"summary", value:"This host is installed with phpMyAdmin and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - 'libraries/Config.class.php' disables X.509 certificate verification
  for GitHub API calls over SSL

  - HTTP requests do not require multiple steps, explicit confirmation,
  or a unique token when performing certain sensitive actions.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow
  attackers to obtain sensitive information by conducting a man-in-the-middle
  attack or by conducting a cross-site scripting attacks, Web cache poisoning, and
  other malicious activities.");

  script_tag(name:"affected", value:"phpMyAdmin versions 4.0.x before 4.0.10.10,
  4.2.x before 4.2.13.3, 4.3.x before 4.3.13.1, and 4.4.x before 4.4.6.1");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin 4.0.10.10, or 4.2.13.3
  or 4.3.13.1 or 4.4.6.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1032404");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security/PMASA-2015-2.php");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_mandatory_keys("phpMyAdmin/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!phpPort = get_app_port(cpe:CPE)) exit(0);

if(!phpVer = get_app_version(cpe:CPE, port:phpPort)) exit(0);

if (version_in_range(version:phpVer, test_version:"4.0.0", test_version2:"4.0.10.9"))
{
  fix = "4.0.10.10";
  VULN = TRUE;
}
if (version_in_range(version:phpVer, test_version:"4.2.0", test_version2:"4.2.13.2"))
{
  fix = "4.2.13.3";
  VULN = TRUE;
}
if (version_in_range(version:phpVer, test_version:"4.3.0", test_version2:"4.3.13.0"))
{
  fix = "4.3.13.1";
  VULN = TRUE;
}
if (version_in_range(version:phpVer, test_version:"4.4.0", test_version2:"4.4.6.0"))
{
  fix = "4.4.6.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(port:phpPort, data:report);
  exit(0);
}

exit(99);