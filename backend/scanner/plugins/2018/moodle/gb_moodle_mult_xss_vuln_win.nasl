###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moodle_mult_xss_vuln_win.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Moodle 3.x Multiple XSS Vulnerabilities - Mar'17 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113180");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-08 14:24:34 +0200 (Tue, 08 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2644", "CVE-2017-2645");
  script_bugtraq_id(96979, 96982);

  script_name("Moodle 3.x Multiple XSS Vulnerabilities - Mar'17 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Moodle is prone to multiple XSS vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on a target host.");
  script_tag(name:"insight", value:"Users have the ability to upload evidence of prior learning.
  In this, both in the text and in the attachment, an XSS script could be embedded.");
  script_tag(name:"affected", value:"Moodle versions 3.1.0 through 3.1.4 and 3.2.0 through 3.2.1.");
  script_tag(name:"solution", value:"Update to version 3.1.5 or 3.2.2 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=349421");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=349422");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.4" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.5", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.2", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
