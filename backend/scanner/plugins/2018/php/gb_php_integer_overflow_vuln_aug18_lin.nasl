###############################################################################
# OpenVAS Vulnerability Test
#
# PHP Integer Overflow Vulnerability Aug18 (Linux)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813902");
  script_version("2019-05-13T06:06:12+0000");
  script_cve_id("CVE-2017-9120");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-13 06:06:12 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-06 18:35:55 +0530 (Mon, 06 Aug 2018)");

  script_name("PHP Integer Overflow Vulnerability Aug18 (Linux)");

  script_tag(name:"summary", value:"This host is installed with PHP and is prone
  to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to
  mysqli_real_escape_string function in mysqli/mysqli_api.c file improperly handles long string.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause denial of service by performing integer overflow and therefore, crashing the application.");

  script_tag(name:"affected", value:"PHP versions 7.0.x through 7.1.15");

  script_tag(name:"solution", value:"No known solution is available as of 13th May, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=74544");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_unixoide");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phpPort = get_app_port(cpe:CPE))) exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:phpPort, exit_no_version:TRUE)) exit(0);
phpVers = infos['version'];
path = infos['location'];

if(version_in_range(version:phpVers, test_version:"7.0", test_version2:"7.1.15")) {
  report = report_fixed_ver(installed_version:phpVers, fixed_version:"None", install_path:path);
  security_message(port:phpPort, data:report);
  exit(0);
}

exit(0);
