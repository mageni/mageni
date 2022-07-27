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
  script_oid("1.3.6.1.4.1.25623.1.0.118251");
  script_version("2021-11-02T03:03:52+0000");
  script_tag(name:"last_modification", value:"2021-11-02 03:03:52 +0000 (Tue, 02 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-10-06 10:01:27 +0200 (Wed, 06 Oct 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_cve_id("CVE-2016-1000110");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python < 2.7.13, 3.3.x < 3.3.7, 3.4.x < 3.4.6, 3.5.x < 3.5.3 HTTPoxy attack (bpo-27568) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"The CGIHandler class in Python is prone to redirection of HTTP
  requests.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The 'CGIHandler' class does not protect against the 'HTTP_PROXY'
  variable name clash in a CGI script, which could allow a remote attacker to redirect HTTP requests.");

  script_tag(name:"affected", value:"Python prior to version 2.7.13, versions 3.3.x prior to 3.3.7,
  3.4.x prior to 3.4.6 and 3.5.x prior to 3.5.3.");

  script_tag(name:"solution", value:"Update to version 2.7.13, 3.3.7, 3.4.6, 3.5.3 or later.");

  script_xref(name:"URL", value:"https://python-security.readthedocs.io/vuln/httpoxy.html");
  script_xref(name:"Advisory-ID", value:"bpo-27568");

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

if( version_is_less( version:version, test_version:"2.7.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.3.0", test_version2:"3.3.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.7", install_path:location);
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.4.0", test_version2:"3.4.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.4.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.5.0", test_version2:"3.5.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.5.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
