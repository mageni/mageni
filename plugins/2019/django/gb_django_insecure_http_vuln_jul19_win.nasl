# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113424");
  script_version("2019-07-04T09:04:55+0000");
  script_tag(name:"last_modification", value:"2019-07-04 09:04:55 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-04 10:25:13 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-12781");

  script_name("Django 1.11.x < 1.11.22, 2.1.x < 2.1.10, 2.2.x < 2.2.3 Insecure HTTP Handling Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to insecure handling of HTTP requests.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"An HTTP request is not redirected to HTTPS when the SECURE_PROXY_SSL_HEADER and
  SECURE_SSL_REDIRECT settings are used and the proxy connects to Django via HTTPS.
  In other words, django.http.HttpRequest.scheme has incorrect behavior when a client uses HTTP.");
  script_tag(name:"impact", value:"Successful exploitation may allow a man-in-the-middle attacker to read sensitive information.");
  script_tag(name:"affected", value:"Django versions 1.11.0 through 1.11.21, 2.1.0 through 2.1.9 and 2.2.0 through 2.2.2.");
  script_tag(name:"solution", value:"Update to version 1.11.22, 2.1.10 or 2.2.3 respectively.");

  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/07/01/3");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2019/jul/01/security-releases/");

  exit(0);
}

CPE = "cpe:/a:django_project:django";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.11.0", test_version2: "1.11.21" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.11.22", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.1.0", test_version2: "2.1.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.1.10", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.2.0", test_version2: "2.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.3", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
