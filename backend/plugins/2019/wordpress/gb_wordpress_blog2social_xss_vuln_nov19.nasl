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
  script_oid("1.3.6.1.4.1.25623.1.0.113569");
  script_version("2019-11-15T12:23:02+0000");
  script_tag(name:"last_modification", value:"2019-11-15 12:23:02 +0000 (Fri, 15 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-15 13:14:33 +0000 (Fri, 15 Nov 2019)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-17550");

  script_name("WordPress Blog2Social Plugin < 5.9.0 Cross-Site Scripting (XSS) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin Blog2Social is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability resides within views/b2s/post.calendar.php.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject
  arbitrary HTML or JavaScript into the site.");
  script_tag(name:"affected", value:"WordPress Blog2Social plugin through version 5.8.1.");
  script_tag(name:"solution", value:"Update to version 5.9.0.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9948");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2186043");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/log/blog2social/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/blog2social/#developers");

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

url = dir + "/wp-content/plugins/blog2social/readme.txt";
res = http_get_cache( port: port, item: url );

if( "===Blog2Social" >< res && "Changelog" >< res ) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res, icase: TRUE );
  if( ! vers[1] ) exit( 0 );
  version = vers[1];

  if( version_is_less( version: version, test_version: "5.9.0" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "5.9.0", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
