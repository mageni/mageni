# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149216");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-30 07:33:28 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:P");

  script_cve_id("CVE-2022-39324");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 8.x < 9.2.10, 9.3.0 < 9.3.4 Spoofing Vulnerability (GHSA-4724-7jwc-3fpw)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a spoofing vulnerability in the snapshot
  functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The value of the originalUrl parameter is automatically
  generated. The purpose of the presented originalUrl parameter is to provide a user who views the
  snapshot with the possibility to click on the Local Snapshot button in the Grafana web UI and be
  presented with the dashboard that the snapshot captured. The value of the originalUrl parameter
  can be arbitrarily chosen by a malicious user that creates the snapshot. (Note: This can be done
  by editing the query thanks to a web proxy like Burp.)");

  script_tag(name:"affected", value:"Grafana version 8.x and 9.x.");

  script_tag(name:"solution", value:"Update to version 9.2.10, 9.3.4 or later.");

  script_xref(name:"URL", value:"https://grafana.com/blog/2023/01/25/grafana-security-releases-new-versions-with-fixes-for-cve-2022-23552-cve-2022-41912-and-cve-2022-39324/");
  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-4724-7jwc-3fpw");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.0.0", test_version_up: "9.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2.10", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "9.3.0", test_version_up: "9.3.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.3.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
