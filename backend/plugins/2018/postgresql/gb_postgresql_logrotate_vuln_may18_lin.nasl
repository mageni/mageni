##############################################################################
# OpenVAS Vulnerability Test
#
# PostgreSQL logrotate Vulnerability - May18 (Linux)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = 'cpe:/a:postgresql:postgresql';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141084");
  script_version("2019-05-17T10:45:27+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-05-11 16:05:24 +0700 (Fri, 11 May 2018)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2018-1115");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL logrotate Vulnerability - May18 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("PostgreSQL/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is vulnerable in the adminpack extension, the
pg_catalog.pg_logfile_rotate() function doesn't follow the same ACLs than pg_rorate_logfile. If the adminpack is
added to a database, an attacker able to connect to it could exploit this to force log rotation.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"PostgreSQL version 9.3.x, 9.4.x, 9.5.x, 9.6.x and 10.x.");

  script_tag(name:"solution", value:"Update to version 10.4, 9.6.9, 9.5.13, 9.4.18, 9.3.23 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1851/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE)) exit(0);
version = infos['version'];
install = infos['location'];

if (version =~ "^9\.3\.") {
  if (version_is_less(version: version, test_version: "9.3.23")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.3.23", install_path: install);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.4\.") {
  if (version_is_less(version: version, test_version: "9.4.18")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.4.18", install_path: install);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.5\.") {
  if (version_is_less(version: version, test_version: "9.5.13")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.5.13", install_path: install);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^9\.6\.") {
  if (version_is_less(version: version, test_version: "9.6.9")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "9.6.9", install_path: install);
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^10\.") {
  if (version_is_less(version: version, test_version: "10.4")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "10.4", install_path: install);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
