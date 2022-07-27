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

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118264");
  script_version("2021-11-03T03:03:35+0000");
  script_tag(name:"last_modification", value:"2021-11-03 03:03:35 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2011-3389");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.6.8, 2.7.x < 2.7.3, 3.1.x < 3.1.5, 3.2.x < 3.2.3 'ssl CBC IV attack' (bpo-13885) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to an improper input validation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The SSL protocol, as used in certain configurations, encrypts
  data by using CBC mode with chained initialization vectors, which allows man-in-the-middle
  attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an
  HTTPS session, in conjunction with JavaScript code that uses the HTML5 WebSocket API, the Java
  URLConnection API, or the Silverlight WebClient API, aka 'BEAST' attack.");

  script_tag(name:"affected", value:"Python prior to version 2.6.8, versions 2.7.x prior to 2.7.3,
  3.1.x prior to 3.1.5 and 3.2.x prior to 3.2.3.");

  script_tag(name:"solution", value:"Update to version 2.6.8, 2.7.3, 3.1.5, 3.2.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/ssl-cbc-iv-attack.html");
  script_xref(name:"Advisory-ID", value:"bpo-13885");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"2.6.8" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.6.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.7.0", test_version2:"2.7.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.3", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.1.0", test_version2:"3.1.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.1.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.2.0", test_version2:"3.2.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
