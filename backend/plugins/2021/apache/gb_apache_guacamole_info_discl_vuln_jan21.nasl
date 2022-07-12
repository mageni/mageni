# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:guacamole";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145246");
  script_version("2021-01-25T03:44:51+0000");
  script_tag(name:"last_modification", value:"2021-01-25 11:10:13 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-25 03:41:24 +0000 (Mon, 25 Jan 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2020-11997");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Guacamole <= 1.2.0 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_guacamole_http_detect.nasl");
  script_mandatory_keys("apache/guacamole/detected");

  script_tag(name:"summary", value:"Apache Guacamole is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache Guacamole does not consistently restrict access to connection
  history based on user visibility. If multiple users share access to the same connection, those users may be
  able to see which other users have accessed that connection, as well as the IP addresses from which that
  connection was accessed, even if those users do not otherwise have permission to see other users.");

  script_tag(name:"affected", value:"Apache Guacamole version 1.2.0 and prior.");

  script_tag(name:"solution", value:"Update to version 1.3.0 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r1a9ae9d1608c9f846875c4191cd738f95543d1be06b52dc1320e8117%40%3Cannounce.guacamole.apache.org%3E");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
