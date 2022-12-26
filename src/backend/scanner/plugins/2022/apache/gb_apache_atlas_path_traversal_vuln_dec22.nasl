# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:apache:atlas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124228");
  script_version("2022-12-15T21:33:16+0000");
  script_tag(name:"last_modification", value:"2022-12-15 21:33:16 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-15 06:52:27 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2022-34271");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Atlas 0.8.4 - 2.2.0 Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_atlas_detect.nasl");
  script_mandatory_keys("Apache/Atlas/Installed");

  script_tag(name:"summary", value:"Apache Atlas is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability in import module of Apache Atlas allows an
  authenticated user to write to web server filesystem.");

  script_tag(name:"affected", value:"Apache Atlas versions 0.8.4 through 2.2.0.");

  script_tag(name:"solution", value:"Update to Version 2.3.0, 3.0.0 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-p782-4j23-xqcg");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/ATLAS-4622");

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

if (version_in_range_exclusive(version: version, test_version_lo: "0.8.4", test_version_up: "2.3.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.3.0, 3.0.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
