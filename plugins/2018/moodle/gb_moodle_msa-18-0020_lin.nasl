###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_msa-18-0020_lin.nasl 12545 2018-11-27 09:09:52Z asteins $
#
# Moodle CMS < 3.6, 3.5.x < 3.5.3, 3.4.x < 3.4.6, 3.3.x < 3.3.9 and < 3.1.15 CSRF Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.112443");
  script_version("$Revision: 12545 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-27 10:09:52 +0100 (Tue, 27 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-27 10:03:12 +0200 (Tue, 27 Nov 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-16854");

  script_name("Moodle CMS < 3.6, 3.5.x < 3.5.3, 3.4.x < 3.4.6, 3.3.x < 3.3.9 and < 3.1.15 CSRF Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle CMS is prone to a login CSRF vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The login form is not protected by a token to prevent login cross-site request forgery.");
  script_tag(name:"affected", value:"Moodle CMS 3.5 to 3.5.2, 3.4 to 3.4.5, 3.3 to 3.3.8, 3.1 to 3.1.14 and earlier unsupported versions.");
  script_tag(name:"solution", value:"Update to version 3.6, 3.5.3, 3.4.6, 3.3.9 or 3.1.15 respectively.");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16854");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=378731");
  script_xref(name:"URL", value:"http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-63183");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "3.1.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.15", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.9", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.6", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.3", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
