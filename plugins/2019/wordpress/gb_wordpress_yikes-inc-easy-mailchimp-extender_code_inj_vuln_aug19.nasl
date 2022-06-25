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
  script_oid("1.3.6.1.4.1.25623.1.0.113525");
  script_version("2019-09-16T11:55:50+0000");
  script_tag(name:"last_modification", value:"2019-09-16 11:55:50 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-16 13:46:25 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-15318");

  script_name("WordPress Easy Forms for Mailchimp Plugin < 6.5.3 Code Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The WordPress plugin Easy Forms for Mailchimp is prone to a code injection vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is exploitable via the admin input field.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"WordPress Easy Forms for Mailchimp plugin through version 6.5.2.");
  script_tag(name:"solution", value:"Update to version 6.5.3 or later.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9583");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/yikes-inc-easy-mailchimp-extender/#developers");

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

url = dir + "/wp-content/plugins/yikes-inc-easy-mailchimp-extender/readme.txt";
res = http_get_cache( port: port, item: url );

if( ( "=== Easy Forms" >< res || "=== Easy MailChimp Forms" >< res || "=== YIKES" >< res )
    && "Changelog" >< res ) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res, icase: TRUE );
  if( ! vers[1] ) exit( 0 );
  version = vers[1];

  if( version_is_less( version: version, test_version: "6.5.3" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "6.5.3", file_checked: url );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );