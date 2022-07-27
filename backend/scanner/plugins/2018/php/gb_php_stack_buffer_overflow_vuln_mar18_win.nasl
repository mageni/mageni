###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_stack_buffer_overflow_vuln_mar18_win.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# PHP Stack Buffer Overflow Vulnerability Mar18 (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812820");
  script_version("$Revision: 12391 $");
  script_cve_id("CVE-2018-7584");
  script_bugtraq_id(103204);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-03-09 15:58:06 +0530 (Fri, 09 Mar 2018)");
  script_name("PHP Stack Buffer Overflow Vulnerability Mar18 (Windows)");

  script_tag(name:"summary", value:"The host is installed with php and is prone
  to stack buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because php fails to
  adequately bounds-check user-supplied data before copying it into an
  insufficiently sized buffer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the affected application. Failed
  exploit attempts will result in denial-of-service conditions.");

  script_tag(name:"affected", value:"PHP versions 7.2.x prior to 7.2.3,

  PHP versions 7.0.x prior to 7.0.28,

  PHP versions 5.0.x prior to 5.6.34 and

  PHP versions 7.1.x prior to 7.1.15 on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 7.2.3, 7.0.28,
  5.6.34, 7.1.15 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-7.php");
  script_xref(name:"URL", value:"https://bugs.php.net/bug.php?id=75981");

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_php_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/installed", "Host/runs_windows");
  script_xref(name:"URL", value:"http://www.php.net");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(phport = get_app_port(cpe: CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:phport, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version: vers, test_version: "7.2", test_version2: "7.2.2")){
  fix = "7.2.3";
}
else if(version_in_range(version: vers, test_version: "7.0", test_version2: "7.0.27")){
  fix = "7.0.28";
}
else if(version_in_range(version: vers, test_version: "7.1", test_version2: "7.1.14")){
  fix = "7.1.15";
}
else if(version_in_range(version: vers, test_version: "5.0", test_version2: "5.6.33")){
  fix = "5.6.34";
}

if(fix){
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:phport, data:report);
  exit(0);
}

exit(99);
