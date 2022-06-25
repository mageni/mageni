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

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147673");
  script_version("2022-02-21T07:26:39+0000");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-21 07:25:33 +0000 (Mon, 21 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2022-23634");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Ruby on Rails Information Disclosure Vulnerability (GHSA-rmj8-8hhh-gv5h) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rails_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("rails/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Ruby on Rails is prone to an information disclosure
  vulnerability in puma.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Puma may not always call close on the response body. Rails
  depends on the response body being closed in order for its CurrentAttributes implementation to
  work correctly.");

  script_tag(name:"affected", value:"Ruby on Rails version 5.x through 7.0.x.");

  script_tag(name:"solution", value:"Update to version 5.2.6.2, 6.0.4.6, 6.1.4.6, 7.0.2.2 or later.");

  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-rmj8-8hhh-gv5h");

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

if (version_is_less(version: version, test_version: "5.2.6.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.6.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.0.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.0.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "6.1", test_version_up: "6.1.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.2.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.2.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
