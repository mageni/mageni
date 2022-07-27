###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_disable_comments_plugin_csfr_vuln.nasl 9166 2018-03-21 17:21:09Z cfischer $
#
# WordPress Disable Comments Plugin CSRF Vulnerability
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107302");
  script_version("$Revision: 9166 $");
  script_tag(name:"last_modification", value:"$Date: 2018-03-21 18:21:09 +0100 (Wed, 21 Mar 2018) $");
  script_tag(name:"creation_date", value:"2018-03-20 14:15:46 +0100 (Tue, 20 Mar 2018)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-2550");

  script_tag(name:"qod_type", value: "remote_banner");

  script_tag(name:"solution_type", value: "VendorFix");

  script_name("WordPress Disable Comments Plugin CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The installed Disable Comments plugin for WordPress has a Cross-site
  request forgery (CSRF) vulnerability.");

  script_tag(name:"impact", value:"This flaw allows remote attackers to hijack the authentication of administrators
  for requests that enable comments via a request to the disable_comments_settings page to wp-admin/options-general.php.");

  script_tag(name:"vuldetect", value:"Checks the version.");

  script_tag(name:"affected", value:"WordPress Disable Comments plugin before 1.0.4.");

  script_tag(name:"solution", value:"Update to version 1.0.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/disable-comments/#developers");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if( !port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( !dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-content/plugins/disable-comments/readme.txt";
res = http_get_cache( port:port, item:url );

if( "Disable Comments" >< res && "Changelog" >< res ) {

  vers = egrep( pattern:"^= ([0-9.]+) =", string:res );

  if( !isnull( vers ) ) {
    vers = eregmatch( pattern:"= ([0-9.]+) =", string:vers );
    if( !isnull( vers[1] ) ) {
      if( version_is_less( version:vers[1], test_version:"1.0.4" ) ) {
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        report = report_fixed_ver( file_checked:conclUrl, installed_version:vers[1], fixed_version:"1.0.4" );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );
