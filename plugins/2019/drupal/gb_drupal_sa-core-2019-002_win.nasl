###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_sa-core-2019-002_win.nasl 13837 2019-02-25 07:45:05Z mmartin $
#
# Drupal Multiple Vulnerabilities (SA-CORE-2019-001/SA-CORE-2019-002) (Windows)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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

CPE = 'cpe:/a:drupal:drupal';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141892");
  script_version("$Revision: 13837 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-25 08:45:05 +0100 (Mon, 25 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-18 10:26:41 +0700 (Fri, 18 Jan 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-1000888", "CVE-2019-6339", "CVE-2019-6338");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Drupal Multiple Vulnerabilities (SA-CORE-2019-001/SA-CORE-2019-002) (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("drupal/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Drupal is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Drupal is prone to multiple vulnerabilities:

  - Drupal core uses the third-party PEAR Archive_Tar library. This library has released a security update which
    impacts some Drupal configurations. (CVE-2018-1000888)

  - A remote code execution vulnerability exists in PHP's built-in phar stream wrapper when performing file
    operations on an untrusted phar:// URI.");

  script_tag(name:"affected", value:"Drupal 7.x, 8.5.x and 8.6.x.");

  script_tag(name:"solution", value:"Update to version 7.62, 8.5.9, 8.6.6 or later.");

  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-001");
  script_xref(name:"URL", value:"https://www.drupal.org/sa-core-2019-002");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "7.0", test_version2: "7.61")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.62");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.5", test_version2: "8.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.5.9");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.6", test_version2: "8.6.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.6.6");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
