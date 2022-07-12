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
  script_oid("1.3.6.1.4.1.25623.1.0.118270");
  script_version("2021-11-04T03:03:45+0000");
  script_tag(name:"last_modification", value:"2021-11-04 03:03:45 +0000 (Thu, 04 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-03 13:15:31 +0100 (Wed, 03 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:00 +0000 (Wed, 26 Feb 2020)");

  script_cve_id("CVE-2014-4650");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python CGIHTTPServer 2.7.x < 2.7.8, 3.2.x < 3.2.5, 3.3.x < 3.3.3, 3.4.x < 3.4.2 Multiple Vulnerabilities (June 2014) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Python is prone to multiple vulnerabilities in CGIHTTPServer.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The CGIHTTPServer Python module does not properly handle
  URL-encoded path separators in URLs.");

  script_tag(name:"impact", value:"Attackers might be enabled to disclose a CGI script's source
  code or execute arbitrary CGI scripts in the server's document root.");

  script_tag(name:"affected", value:"Python version 2.7.x before 2.7.8, 3.2.x before 3.2.5,
  3.3.x before 3.3.3 and 3.4.x before 3.4.2.");

  script_tag(name:"solution", value:"Update to Python version 2.7.8, 3.2.5, 3.3.3, 3.4.2 or later.");

  script_xref(name:"URL", value:"https://www.redteam-pentesting.de/en/advisories/rt-sa-2014-008/-python-cgihttpserver-file-disclosure-and-potential-code-execution");
  script_xref(name:"URL", value:"http://bugs.python.org/issue21766");

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

if( version_in_range( version:version, test_version:"2.7.0", test_version2:"2.7.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.2.0", test_version2:"3.2.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.2.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.3.0", test_version2:"3.3.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}
if( version_in_range( version:version, test_version:"3.4.0", test_version2:"3.4.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
