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

CPE = "cpe:/a:horde:gollem";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143997");
  script_version("2020-05-28T03:27:30+0000");
  script_tag(name:"last_modification", value:"2020-05-28 03:27:30 +0000 (Thu, 28 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-28 03:26:40 +0000 (Thu, 28 May 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2020-8034");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Gollem < 3.0.13 XSS Vulnerability (Windows)");

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_horde_gollem_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("horde/gollem/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Horde Gollem is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Gollem is affected by a reflected cross-site scripting (XSS) vulnerability
  via the HTTP GET dir parameter in the browser functionality, affecting breadcrumb output.");

  script_tag(name:"impact", value:"An attacker can obtain access to a victim's webmail account by making them
  visit a malicious URL.");

  script_tag(name:"affected", value:"Horde Gollem prior to version 3.0.13.");

  script_tag(name:"solution", value:"Update to version 3.0.13 or later.");

  script_xref(name:"URL", value:"https://lists.horde.org/archives/announce/2020/001289.html");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version:"3.0.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
