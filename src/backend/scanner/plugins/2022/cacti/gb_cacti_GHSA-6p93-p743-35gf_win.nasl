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

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148991");
  script_version("2022-12-06T10:11:16+0000");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-06 04:14:06 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2022-46169");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.2.23 Command Injection Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to an unauthenticated command injection
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A command injection vulnerability allows an unauthenticated
  user to execute arbitrary code on a server running Cacti, if a specific data source was selected
  for any monitored device.");

  script_tag(name:"impact", value:"This command injection vulnerability allows an unauthenticated
  user to execute arbitrary commands if a poller_item with the action type POLLER_ACTION_SCRIPT_PHP
  is configured.");

  script_tag(name:"affected", value:"Cacti version 1.2.22 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.23 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/security/advisories/GHSA-6p93-p743-35gf");

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

if (version_is_less(version: version, test_version: "1.2.23")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.23", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
