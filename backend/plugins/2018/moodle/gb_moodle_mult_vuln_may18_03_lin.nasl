###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_mult_vuln_may18_03_lin.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Moodle 3.x Multiple Vulnerabilities - Sep'17 (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113185");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-15 11:42:45 +0200 (Tue, 15 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-12156", "CVE-2017-12157");
  script_bugtraq_id(100848, 100867);

  script_name("Moodle 3.x Multiple Vulnerabilities - Sep'17 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  Form on the feedback 'non-respondents' page does not escape the value of subject thus creating self-XSS.
  This can be used to attack another user by tricking them into opening malicious URL whilst in an open Moodle session.

  Number of course reports allowed teachers to view details about users in the groups they can't access.

  user_can_view_profile() incorrectly assumes $course as shared course. This fix may affect plugins using this API function,
  there is no exploit in standard Moodle.");
  script_tag(name:"affected", value:"Moodle versions through 3.1.7, 3.2.0 through 3.2.4 and 3.3.0 through 3.3.1.");
  script_tag(name:"solution", value:"Update to version 3.1.8, 3.2.5 or 3.3.2 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=358585");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=358586");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=358587");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "3.1.8" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.8", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.5", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.3.0", test_version2: "3.3.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.3.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
