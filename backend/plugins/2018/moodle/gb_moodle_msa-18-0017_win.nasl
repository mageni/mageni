###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_msa-18-0017_win.nasl 12697 2018-12-07 07:56:28Z mmartin $
#
# Moodle CMS 3.5.x < 3.5.2, 3.4.x < 3.4.5, 3.2.x < 3.3.8 and < 3.1.14 RCE Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.112381");
  script_version("$Revision: 12697 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 08:56:28 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-09-18 11:17:22 +0200 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-14630");

  script_name("Moodle CMS 3.5.x < 3.5.2, 3.4.x < 3.4.5, 3.2.x < 3.3.8 and < 3.1.14 RCE Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Moodle CMS is prone to a remote code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"When importing legacy 'drag and drop into text' (ddwtos) type quiz questions,
  it was possible to inject and execute PHP code from within the imported questions, either intentionally or by importing questions from an untrusted source.");
  script_tag(name:"affected", value:"Moodle CMS 3.5 to 3.5.1, 3.4 to 3.4.4, 3.2 to 3.3.7, 3.1 to 3.1.13 and earlier unsupported versions.");
  script_tag(name:"solution", value:"Update to version 3.1.14, 3.3.8, 3.4.5 or 3.5.2 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-14630");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=376023");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "3.1.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.14", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.3.7" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.8", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.5", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
