# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142221");
  script_version("2019-04-15T07:08:44+0000");
  script_tag(name:"last_modification", value:"2019-04-15 07:08:44 +0000 (Mon, 15 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-08 15:18:08 +0000 (Mon, 08 Apr 2019)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-0217");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server < 2.4.39 mod_auth_digest Access Control Bypass Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"In Apache HTTP Server, a race condition in mod_auth_digest when running in a
threaded server could allow a user with valid credentials to authenticate using another username, bypassing
configured access control restrictions.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache HTTP server version 2.4.38 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.39 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

affected = make_list('2.4.38',
                     '2.4.37',
                     '2.4.35',
                     '2.4.34',
                     '2.4.33',
                     '2.4.30',
                     '2.4.29',
                     '2.4.28',
                     '2.4.27',
                     '2.4.26',
                     '2.4.25',
                     '2.4.23',
                     '2.4.20',
                     '2.4.18',
                     '2.4.17',
                     '2.4.16',
                     '2.4.12',
                     '2.4.10',
                     '2.4.9',
                     '2.4.7',
                     '2.4.6',
                     '2.4.4',
                     '2.4.3',
                     '2.4.2',
                     '2.4.1',
                     '2.4.0' );

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.39");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
