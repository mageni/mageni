###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_mult_vuln_jul18_01_lin.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Moodle CMS <= 3.1.12, 3.2.x, 3.3.x <= 3.3.6, 3.4.x <= 3.4.3, 3.5.0 Multiple Vulnerabilities (Linux)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113228");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-07-12 10:10:32 +0200 (Thu, 12 Jul 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-10890", "CVE-2018-10891");

  script_name("Moodle CMS <= 3.1.12, 3.2.x, 3.3.x <= 3.3.6, 3.4.x <= 3.4.3, 3.5.0 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - It's possible for the core_course_get_categories web service
    to return hidden categories, which should be omitted when fetching course categories.

  - When a quiz question bank is imported, it is possible for the question preview
    that is displayed to execute JavaScript that is written into the question bank.");
  script_tag(name:"affected", value:"Moodle CMS through version 3.1.12, 3.2.0 through 3.3.6, 3.4.0 through 3.4.3 and 3.5.0.");
  script_tag(name:"solution", value:"Update to version 3.1.13, 3.3.7, 3.4.4 or 3.5.1 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-10890");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-10891");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "3.1.13" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.13", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.3.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.7", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.4", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_is_equal( version: version, test_version: "3.5.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.1", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
