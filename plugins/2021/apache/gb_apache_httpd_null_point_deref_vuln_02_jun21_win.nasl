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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112904");
  script_version("2021-06-10T14:00:16+0000");
  script_tag(name:"last_modification", value:"2021-06-11 10:19:43 +0000 (Fri, 11 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-10 09:23:11 +0000 (Thu, 10 Jun 2021)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_cve_id("CVE-2021-31618");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server < 2.4.48 NULL Pointer Dereference Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_http_server_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/http_server/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Apache HTTP Server is prone to a NULL pointer dereference
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server protocol handler for the HTTP/2 protocol
  checks received request headers against the size limitations as configured for the server and
  used for the HTTP/1 protocol as well. On violation of these restrictions an HTTP response is
  sent to the client with a status code indicating why the request was rejected.

  This rejection response was not fully initialised in the HTTP/2 protocol handler if the offending
  header was the very first one received or appeared in a footer. This led to a NULL pointer
  dereference on initialised memory, crashing reliably the child process.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to crash the server.");

  script_tag(name:"affected", value:"Apache HTTP Server before version 2.4.48 on Windows.");

  script_tag(name:"solution", value:"Update to version 2.4.48 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:apache:http_server";

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.4.48" ) ) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.4.48", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
