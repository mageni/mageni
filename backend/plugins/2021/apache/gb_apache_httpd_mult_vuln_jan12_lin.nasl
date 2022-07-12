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

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147057");
  script_version("2021-11-01T05:54:41+0000");
  script_tag(name:"last_modification", value:"2021-11-01 11:21:25 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 05:32:29 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-3607", "CVE-2012-0031", "CVE-2012-0053");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server Multiple Vulnerabilities (Jan 2012) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2011-3607: An integer overflow flaw was found which, when the mod_setenvif module is
  enabled, could allow local users to gain privileges via a .htaccess file.

  - CVE-2012-0031: A flaw was found in the handling of the scoreboard. An unprivileged child
  process could cause the parent process to crash at shutdown rather than terminate cleanly.

  - CVE-2012-0053: A flaw was found in the default error response for status code 400. This flaw
  could be used by an attacker to expose 'httpOnly' cookies when no custom ErrorDocument is
  specified.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.0.35 through 2.2.21.");

  script_tag(name:"solution", value:"Update to version 2.2.22 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_22.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.0.35", test_version2: "2.2.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.22", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
