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
  script_oid("1.3.6.1.4.1.25623.1.0.113493");
  script_version("2019-09-04T10:49:22+0000");
  script_tag(name:"last_modification", value:"2019-09-04 10:49:22 +0000 (Wed, 04 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-04 12:39:40 +0000 (Wed, 04 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15820");

  script_name("WordPress Login or Logout Menu Item Plugin < 1.2.0 Authentication Bypass Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin Login or Logout Menu Item is prone to an authentication bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"There is no authentication requirement for lolmi_save_settings.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to modify
  the settings without authentication.");
  script_tag(name:"affected", value:"WordPress Login or Logout Menu Item plugin through version 1.1.1.");
  script_tag(name:"solution", value:"Update to version 1.2.0.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9500");
  script_xref(name:"URL", value:"https://blog.nintechnet.com/unauthenticated-options-change-in-wordpress-login-or-logout-menu-item-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/login-or-logout-menu-item/#developers");

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

url = dir + "/wp-content/plugins/login-or-logout-menu-item/readme.txt";
res = http_get_cache( port: port, item: url );

if( "=== Login or Logout Menu Item" >< res && "Changelog" >< res ) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res, icase: TRUE );
  if( ! vers[1] ) exit( 0 );
  version = vers[1];

  if( version_is_less( version: version, test_version: "1.2.0" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "1.2.0", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );