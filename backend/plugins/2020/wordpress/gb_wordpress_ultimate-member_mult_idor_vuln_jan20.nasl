# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113626");
  script_version("2020-01-20T12:44:24+0000");
  script_tag(name:"last_modification", value:"2020-01-20 12:44:24 +0000 (Mon, 20 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-20 12:33:35 +0000 (Mon, 20 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-6859");

  script_name("WordPress Ultimate Member Plugin <= 2.1.2 Multiple Insecure Direct Object Reference Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin Ultimate Member is prone to multiple
  Insecure Direct Object Reference vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities reside in includes/core/class-files.php.");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote attacker to
  change other users' profiles and cover photos via
  a modified user_id parameter.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin through version 2.1.2.");

  script_tag(name:"solution", value:"No known solution is available as of 20th January, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-member/#developers");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "version_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/wp-content/plugins/ultimate-member/readme.txt";
res = http_get_cache( port: port, item: url );

if( "=== Ultimate Member" >< res && "Changelog" >< res ) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res, icase: TRUE );
  if( ! vers[1] ) exit( 0 );
  version = vers[1];

  if( version_is_less_equal( version: version, test_version: "2.1.2" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "None Available", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );