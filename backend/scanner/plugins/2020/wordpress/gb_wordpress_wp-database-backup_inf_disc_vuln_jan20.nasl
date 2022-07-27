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
  script_oid("1.3.6.1.4.1.25623.1.0.113632");
  script_version("2020-01-24T11:09:11+0000");
  script_tag(name:"last_modification", value:"2020-01-24 11:09:11 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-24 10:14:17 +0000 (Fri, 24 Jan 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2020-7241");

  script_name("WordPress WP Database Backup Plugin <= 5.5 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin WP Database Backup is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Downloads are by default stored locally in the directory wp-content/uploads/db-backup/.
  This might allow attackers to ready ZIP archives by guessing random ID numbers, guessing
  data strings with a 2020_{0..1}{0..2}_{0..3}{0..9} format, guessing UNIX timestamps and
  making HTTPS requests with the complete guesses URL.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to read sensitive information.");

  script_tag(name:"affected", value:"WordPress WP Database Backup plugin through version 5.5.");

  script_tag(name:"solution", value:"No known solution is available as of 24th January, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-database-backup/#developers");
  script_xref(name:"URL", value:"https://github.com/V1n1v131r4/Exploiting-WP-Database-Backup-WordPress-Plugin/blob/master/README.md");

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

url = dir + "/wp-content/plugins/wp-database-backup/readme.txt";
res = http_get_cache( port: port, item: url );

if( "=== WP Database Backup" >< res && "Changelog" >< res ) {

  #nb: Workaround because the newest version is at the bottom
  while(TRUE) {
    new_ver = eregmatch( pattern: "= ([0-9.]+) =", string: res, icase: TRUE );

    #nb: 4.6.5: Time of Changelog order reversal (newest version at the top);
    if( !new_ver[1] ) break;
    test_version = new_ver[1];
    if( version_is_greater_equal( version: test_version, test_version: "4.6.5" ) ) {
      vers = new_ver;
      break;
    }

    new_res = ereg_replace( pattern: "= " + test_version + " =", string: res, replace: "", icase: TRUE );
    if( strlen( res ) == strlen( new_res ) )
      break;
    vers = new_ver;
    res = new_res;
  }

  if( ! vers[1] ) exit( 0 );
  version = vers[1];

  if( version_is_less_equal( version: version, test_version: "5.5" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "None Available", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
