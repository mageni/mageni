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
  script_oid("1.3.6.1.4.1.25623.1.0.113396");
  script_version("2019-05-22T13:15:08+0000");
  script_tag(name:"last_modification", value:"2019-05-22 13:15:08 +0000 (Wed, 22 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-22 14:32:00 +0200 (Wed, 22 May 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-11886");

  script_name("WordPress WaspThemes Visual CSS Style Editor Plugin < 7.2.1 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin WaspThemes Visual CSS Style Editor
  (aka yellow-pencil-visual-theme-customizer) is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target system.");

  script_tag(name:"insight", value:"The vulnerability exists within yp_option_update.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain admin access
  via yp_remote_get.");

  script_tag(name:"affected", value:"WaspThemes Visual CSS Style Editor through version 7.2.0.");

  script_tag(name:"solution", value:"Update to version 7.2.1.");

  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2019/04/09/recently-closed-visual-css-style-editor-wordpress-plugin-contains-privilege-escalation-vulnerability-that-leads-to-option-update-vulnerability/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2019/04/zero-day-vulnerability-in-yellow-pencil-visual-theme-customizer-exploited-in-the-wild/");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9256");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/yellow-pencil-visual-theme-customizer/#developers");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-content/plugins/yellow-pencil-visual-theme-customizer/readme.txt";
res = http_get_cache( port: port, item: url );

if( "=== Visual CSS Style Editor" >< res && "Changelog" >< res ) {

  # nb: Plugin-Dev is using the current WordPress version in "Stable tag:"
  vers = eregmatch(pattern: "= ([0-9.]+) =", string: res);

  if( vers[1] && version_is_less( version: vers[1], test_version: "7.2.1" ) ) {
    report = report_fixed_ver( installed_version: vers[1], fixed_version: "7.2.1", file_checked: url );
    security_message( port: port, data: report );
    exit(0);
  }
}

exit(99);
