###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_fpm_loop_dos_vuln_lin.nasl 12762 2018-12-11 15:47:20Z cfischer $
#
# PHP 'PHP-FPM' Denial of Service Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.812520");
  script_version("$Revision: 12762 $");
  script_cve_id("CVE-2015-9253");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-11 16:47:20 +0100 (Tue, 11 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 18:02:59 +0530 (Tue, 20 Feb 2018)");
  script_name("PHP 'PHP-FPM' Denial of Service Vulnerability (Linux)");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=73342");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=70185");
  script_xref(name:"URL", value:"https://github.com/php/php-src/pull/3287");
  script_xref(name:"URL", value:"https://www.futureweb.at/security/CVE-2015-9253");
  script_xref(name:"URL", value:"https://vuldb.com//?id.113566");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exist due to the php-fpm master
  process restarts a child process in an endless loop when using program
  execution functions with a non-blocking STDIN stream.");

  script_tag(name:"impact", value:"Successfully exploitation will allow an
  attackers to consume 100% of the CPU, and consume disk space with a large
  volume of error logs, as demonstrated by an attack by a customer of a
  shared-hosting facility.");

  script_tag(name:"affected", value:"PHP versions 5.x up to and including 5.6.36. All 7.0.x versions,
  7.1.x before 7.1.20, 7.2.x before 7.2.8 and 7.3.x before 7.3.0alpha3 on Windows.");

  script_tag(name:"solution", value:"Update to PHP 7.1.20, 7.2.8 or 7.3.0alpha3.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpPort = get_app_port(cpe:CPE))) exit(0);
if(!infos = get_app_version_and_location(cpe:CPE, port:phpPort, exit_no_version:TRUE)) exit(0);
phpVers = infos['version'];
path = infos['location'];

# nb: Fix is only shipped / released in the branches 7.1.x and up and fixed starting with 7.1.20.
if(version_in_range(version:phpVers, test_version:"5.0", test_version2:"7.1.19")){
  fix = "7.1.20";
} else if(phpVers =~ "^7\.2\." && version_is_less(version:phpVers, test_version:"7.2.8")){
  fix = "7.2.8";
} else if(phpVers =~ "^7\.3\." && version_is_less(version:phpVers, test_version:"7.3.0alpha3")){
  fix = "7.3.0alpha3";
}

if(fix){
  report = report_fixed_ver(installed_version:phpVers, fixed_version:fix, install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}

exit(99);