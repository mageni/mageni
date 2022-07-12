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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146863");
  script_version("2021-10-07T11:46:02+0000");
  script_tag(name:"last_modification", value:"2021-10-08 11:46:07 +0000 (Fri, 08 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-07 11:38:53 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2021-39226");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana 2.0.1 < 7.5.11, 8.x < 8.1.6 Snapshot Authentication Bypass Vulnerability (GHSA-69j6-29vr-p3j9)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to an authentication bypass vulnerability in
  the snapshot functionality.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Unauthenticated and authenticated users are able to view the
  snapshot with the lowest database key by accessing the literal paths:

    /dashboard/snapshot/:key, or

    /api/snapshots/:key

  If the snapshot 'public_mode' configuration setting is set to true (vs default of false),
  unauthenticated users are able to delete the snapshot with the lowest database key by accessing
  the literal path:

    /api/snapshots-delete/:deleteKey

  Regardless of the snapshot 'public_mode' setting, authenticated users are able to delete the
  snapshot with the lowest database key by accessing the literal paths:

    /api/snapshots/:key, or

    /api/snapshots-delete/:deleteKey

  The combination of deletion and viewing enables a complete walk through all snapshot data while
  resulting in complete snapshot data loss.");

  script_tag(name:"affected", value:"Grafana version 2.0.1 through 7.5.10 and 8.x through 8.1.5.");

  script_tag(name:"solution", value:"Update to version 7.5.11, 8.1.6 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-69j6-29vr-p3j9");

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

if (version_in_range(version: version, test_version: "2.0.1", test_version2: "7.5.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.5.11", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "8.0", test_version2: "8.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
