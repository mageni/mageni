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
  script_oid("1.3.6.1.4.1.25623.1.0.113464");
  script_version("2019-08-27T09:03:51+0000");
  script_tag(name:"last_modification", value:"2019-08-27 09:03:51 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 10:48:09 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-9307", "CVE-2015-9308", "CVE-2015-9309");

  script_name("WordPress WP Google Map Plugin < 2.3.10 Multiple CSRF Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin WP Google Map Plugin is prone to multiple cross-site request forgery (CSRF) vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerabilities reside in the add/edit location, add/edit map and edit/edit category features.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to perform actions in the context of another user.");
  script_tag(name:"affected", value:"WordPress WP Google Map Plugin through version 2.3.9.");
  script_tag(name:"solution", value:"Update to version 2.3.10 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-google-map-plugin/#developers");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "version_func.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe: CPE, port: port ) ) exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-content/plugins/wp-google-map-plugin/readme.txt";
res = http_get_cache( port: port, item: url );

if( res =~ "Plugin Name: +WP Google Map Plugin" && "Changelog" >< res ) {

  vers = eregmatch(pattern: "= ([0-9.]+) =", string: res);

  if( vers[1] && version_is_less( version: vers[1], test_version: "2.3.10" ) ) {
    report = report_fixed_ver( installed_version: vers[1], fixed_version: "2.3.10", install_path: dir );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
