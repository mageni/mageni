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
  script_oid("1.3.6.1.4.1.25623.1.0.113469");
  script_version("2019-08-27T10:32:10+0000");
  script_tag(name:"last_modification", value:"2019-08-27 10:32:10 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 11:34:59 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2015-9314");

  script_name("WordPress NewStatPress Plugin < 1.0.4 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin NewStatPress is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  inject arbitrary HTML or JavaScript into the site.");
  script_tag(name:"affected", value:"WordPress NewStatPress plugin through version 1.0.3.");
  script_tag(name:"solution", value:"Update to version 1.0.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/newstatpress/#developers");

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

url = dir + "/wp-content/plugins/newstatpress/readme.txt";
res = http_get_cache( port: port, item: url );

if( "NewStatPress is a new version of StatPress" >< res && "Changelog" >< res) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res, icase: TRUE );

  if( version_is_less( version: vers[1], test_version: "1.0.4" ) ) {
    report = report_fixed_ver( installed_version: vers[1], fixed_version: "1.0.4", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
