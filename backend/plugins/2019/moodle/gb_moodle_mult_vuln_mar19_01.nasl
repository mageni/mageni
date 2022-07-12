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
  script_oid("1.3.6.1.4.1.25623.1.0.113360");
  script_version("2019-04-02T11:19:26+0000");
  script_tag(name:"last_modification", value:"2019-04-02 11:19:26 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-02 12:22:11 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-3808", "CVE-2019-3810");

  script_name("Moodle CMS 3.6.x < 3.6.2, 3.5.x < 3.5.4, 3.4.x < 3.4.7 and < 3.1.15 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle CMS is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - The 'manage groups' capability does not have the 'XSS risk' flag assigned to it,
    but does have that access in certain places.

  - The /userpix/ page does not escape a user's full name, which is included as text
    when hovering over profile images.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject arbitrary
  JavaScript and HTML into the web page.");
  script_tag(name:"affected", value:"Moodle CMS versions through 3.1.15, 3.4.0 through 3.4.6,
  3.5.0 through 3.5.3 and 3.6.0 through 3.6.1.");
  script_tag(name:"solution", value:"Update to version 3.1.16, 3.4.7, 3.5.4 or 3.6.2 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=381228#p1536765");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=381230#p1536767");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "3.1.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.16" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.6" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.4.7" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.5.0", test_version2: "3.5.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.5.4" );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.6.0", test_version2: "3.6.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.6.2" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
