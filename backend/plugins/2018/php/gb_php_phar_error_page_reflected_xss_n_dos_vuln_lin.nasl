###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_phar_error_page_reflected_xss_n_dos_vuln_lin.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# PHP 'PHAR' Error Page Reflected XSS And DoS Vulnerabilities (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812735");
  script_version("$Revision: 12120 $");
  script_cve_id("CVE-2018-5712", "CVE-2018-5711");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-19 14:45:34 +0530 (Fri, 19 Jan 2018)");
  script_name("PHP 'PHAR' Error Page Reflected XSS And DoS Vulnerabilities (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to cross site scripting and denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An input validation error on the PHAR 404 error page via the URI of a request
    for a .phar file.

  - An integer signedness error in gd_gif_in.c in the GD Graphics Library
    (aka libgd).");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  attacker to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site. This may allow the attacker to
  steal cookie-based authentication credentials and to launch other attacks
  and will also lead to a denial of service and exhausting the server resources.");

  script_tag(name:"affected", value:"PHP versions before 5.6.33, 7.0.x before
  7.0.27, 7.1.x before 7.1.13, and 7.2.x before 7.2.1");

  script_tag(name:"solution", value:"Upgrade to PHP version 5.6.33, 7.0.27,
  7.1.13 or 7.2.1 or later.");

  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=74782");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75571");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpPort = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:phpPort, exit_no_version:TRUE)) exit(0);
phpVers = infos['version'];
path = infos['location'];

if(version_is_less(version:phpVers, test_version:"5.6.33")){
  fix = "5.6.33";
}

else if(version_in_range(version:phpVers, test_version:"7.0", test_version2:"7.0.26")){
  fix = "7.0.27";
}

else if(phpVers =~ "^7\.1" && version_is_less(version:phpVers, test_version:"7.1.13")){
  fix = "7.1.13";
}

else if(phpVers =~ "^7\.2" && version_is_less(version:phpVers, test_version:"7.2.1")){
  fix = "7.2.1";
}

if(fix)
{
  report = report_fixed_ver(installed_version:phpVers, fixed_version:fix, install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}
exit(0);
