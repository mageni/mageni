# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:postgresql:postgresql";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144707");
  script_version("2020-10-07T07:16:59+0000");
  script_tag(name:"last_modification", value:"2020-10-07 09:36:44 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-07 06:57:51 +0000 (Wed, 07 Oct 2020)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2020-14349");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PostgreSQL 10.x < 10.14, 11.x < 11.9, 12.x < 12.4 Search Path Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Databases");
  script_dependencies("postgresql_detect.nasl", "secpod_postgresql_detect_lin.nasl", "os_detection.nasl");
  script_mandatory_keys("postgresql/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PostgreSQL is prone to an uncontrolled search path element vulnerability in
  logical replication.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The PostgreSQL search_path setting determines schemas searched for tables,
  functions, operators, etc. The CVE-2018-1058 fix caused most PostgreSQL-provided client applications to sanitize
  search_path, but logical replication continued to leave search_path unchanged. Users of a replication publisher
  or subscriber database can create objects in the public schema and harness them to execute arbitrary SQL
  functions under the identity running replication, often a superuser. Installations having adopted a documented
  secure schema usage pattern are not vulnerable.");

  script_tag(name:"affected", value:"PostgreSQL versions 10.x prior to 10.14, 11.x prior to 11.9 and 12.x
  prior to 12.4.");

  script_tag(name:"solution", value:"Update to version 10.14, 11.9, 12.4 or later.");

  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/postgresql-124-119-1014-9619-9523-and-13-beta-3-released-2060/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "10.0", test_version2: "10.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.14", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "11.0", test_version2: "11.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "11.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "12.0", test_version2: "12.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
