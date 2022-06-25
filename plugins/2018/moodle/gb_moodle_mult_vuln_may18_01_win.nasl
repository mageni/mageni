###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_mult_vuln_may18_01_win.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Moodle 2.x / 3.x Multiple Vulnerabilities - May'16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113176");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-08 13:00:00 +0200 (Tue, 08 May 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2016-3729", "CVE-2016-3731", "CVE-2016-3732", "CVE-2016-3733", "CVE-2016-3734");
  script_bugtraq_id(91281);

  script_name("Moodle 2.x / 3.x Multiple Vulnerabilities - May'16 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Moodle CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  The user editing form allows remote authenticated users to edit profile fields locked by the administrator.

  Moodle allows remote attackers to obtain the names of hidden forums and forum discussions.

  The capability check to access other badges allows remote authenticated users to read the badges of other users.

  The 'restore teacher' feature allows remote authenticated users to overwrite the course idnumber.

  Cross-site request forgery (CSRF) vulnerability in markposts.php allows remote attackers to
  hijack the authentication of users for requests that marks forum posts as read.");
  script_tag(name:"impact", value:"Successful exploitation could have effects ranging from information disclosure to
  disallowed modifications.");
  script_tag(name:"affected", value:"Moodle versions through 2.7.13, 2.8.0 through 2.8.11, 2.9.0 through 2.9.5 and 3.0.0 through 3.0.3.");
  script_tag(name:"solution", value:"Update to version 2.7.14, 2.8.12, 2.9.6 or 3.0.4 respectively.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/05/17/4");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1335933");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "2.7.14" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.14", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "2.8.11" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.8.12", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.9.0", test_version2: "2.9.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.9.6", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.0.0", test_version2: "3.0.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.0.4", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
