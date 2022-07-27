###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_loginizer_stored_xss_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# WordPress Loginizer Plugin Stored XSS Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113197");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-24 16:32:39 +0200 (Thu, 24 May 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11366");

  script_name("WordPress Loginizer Plugin Stored XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress Loginizer plugin is prone to a stored Cross-Site Scripting (XSS) Vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The problem exists due to mishandled logging.");
  script_tag(name:"affected", value:"Loginizer versions 1.3.8 through 1.3.9.");
  script_tag(name:"solution", value:"Update to version 1.4.0.");

  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9088");
  script_xref(name:"URL", value:"https://blog.dewhurstsecurity.com/2018/05/22/loginizer-wordpress-plugin-xss-vulnerability.html");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/1878502/loginizer");

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

res = http_get_cache(port: port, item: dir + "/wp-content/plugins/loginizer/readme.txt");

if ("Loginizer" >< res && "Changelog" >< res) {
  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if( isnull( vers[1] ) ) exit( 0 );
  version = vers[1];

  if( version_in_range( version: version, test_version: "1.3.8", test_version2: "1.3.9" ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: "1.4.0" );
    security_message( data: report, port: port );
    exit( 0 );
  }
}

exit( 99 );
