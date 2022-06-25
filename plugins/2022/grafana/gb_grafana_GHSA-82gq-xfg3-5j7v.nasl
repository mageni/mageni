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

CPE = "cpe:/a:grafana:grafana";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147986");
  script_version("2022-04-13T09:04:54+0000");
  script_tag(name:"last_modification", value:"2022-04-13 10:28:29 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-13 06:44:12 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2022-24812");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Grafana OAuth Privilege Escalation Vulnerability (GHSA-82gq-xfg3-5j7v)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_grafana_http_detect.nasl");
  script_mandatory_keys("grafana/detected");

  script_tag(name:"summary", value:"Grafana is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When fine-grained access control is enabled and a client uses
  Grafana API Key to make requests, the permissions for that API Key are cached for 30 seconds for
  the given organization. Because of the way the cache ID is constructed, the consequent requests
  with any API Key evaluate to the same permissions as the previous requests. This can lead to an
  escalation of privileges, when for example a first request is made with Admin permissions, and
  the second request with different API Key is made with Viewer permissions, the second request
  will get the cached permissions from the previous Admin, essentially accessing higher privilege
  than it should.");

  script_tag(name:"affected", value:"Grafana Enterprise version 8.1.0-beta1 through 8.4.5.");

  script_tag(name:"solution", value:"Update to version 8.4.6 or later.");

  script_xref(name:"URL", value:"https://github.com/grafana/grafana/security/advisories/GHSA-82gq-xfg3-5j7v");

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

if (version_in_range_exclusive(version: version, test_version_lo: "8.1.0", test_version_up: "8.4.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.4.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
