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
  script_oid("1.3.6.1.4.1.25623.1.0.112704");
  script_version("2020-02-28T13:16:52+0000");
  script_tag(name:"last_modification", value:"2020-02-28 13:16:52 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-28 10:59:11 +0000 (Fri, 28 Feb 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-9003");

  script_name("WordPress Modula Image Gallery Plugin < 2.2.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin Modula Image Gallery is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow an authenticated
  low-privileged user to inject arbitrary JavaScript code that is viewed by other users.");

  script_tag(name:"affected", value:"WordPress Modula Image Gallery plugin before version 2.2.5.");

  script_tag(name:"solution", value:"Update to version 2.2.5 or later.");

  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-20-041");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/10077");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/modula-best-grid-gallery/#developers");

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

url = dir + "/wp-content/plugins/modula-best-grid-gallery/README.txt";
res = http_get_cache( port: port, item: url );

if( res =~ "Modula (Image )?Gallery" && "Changelog" >< res ) {

  #nb: Workaround because from version 2.0 onwards the Stable tag is being used and the detailed Changelog has been moved.
  if( ! vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res ) ) {
    cl = eregmatch( pattern: "== Changelog(.*)", string: res );
    vers = eregmatch( pattern: "= ([0-9.]+) =", string: cl[1] );
  }

  if( vers[1] && version_is_less( version: vers[1], test_version: "2.2.5" ) ) {
    report = report_fixed_ver( installed_version: vers[1], fixed_version: "2.2.5", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
