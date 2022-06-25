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
  script_oid("1.3.6.1.4.1.25623.1.0.113393");
  script_version("2019-05-24T13:14:04+0000");
  script_tag(name:"last_modification", value:"2019-05-24 13:14:04 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-20 10:36:33 +0200 (Mon, 20 May 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_cve_id("CVE-2019-7411");

  script_name("WordPress MyThemeShop Launcher Plugin <= 1.0.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The MyThemeShop Launcher plugin for WordPress is prone to
  a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple stored cross-site scripting vulnerabilities allow remote
  authenticated users to inject arbitrary web script or HTML via following fields:

  - Title

  - Favicon

  - Meta Description

  - Subscribe Form (Name field label, Last name field label, Email field label)

  - Contact Form (Name field label, Email field label)

  - Social Links (Facebook Page URL, Twitter Page URL, Instagram Page URL, YouTube Page URL,
    LinkedIn Page URL, Google+ Page URL, RSS URL)");
  script_tag(name:"affected", value:"WordPress MyThemeShop Launcher plugin through version 1.0.8.");
  script_tag(name:"solution", value:"No known solution is available as of 20th May, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://metamorfosec.com/Files/Advisories/METS-2019-002-Multiple_Stored_XSS_Vulnerabilities_in_the_MyThemeShop_Launcher_plugin_v1.0.8_for_WordPress.txt");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-content/plugins/launcher/readme.txt";
res = http_get_cache( port: port, item: url );

if( "=== Launcher" >< res && "Changelog" >< res ) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if( vers[1] && version_is_less_equal( version: vers[1], test_version: "1.0.8" ) ) {
    report = report_fixed_ver( installed_version: vers[1], fixed_version: "NoneAvailable", file_checked: url );
    security_message( port: port, data: report );
    exit(0);
  }
}

exit(99);
