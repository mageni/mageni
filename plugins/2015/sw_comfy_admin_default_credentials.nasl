###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_comfy_admin_default_credentials.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# ComfortableMexicanSofa CMS Engine Admin Default Credentials
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:comfy:comfy";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111072");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ComfortableMexicanSofa CMS Engine Admin Default Credentials");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-15 19:00:00 +0100 (Tue, 15 Dec 2015)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 3000);
  script_require_keys("comfy/installed");

  script_tag(name:"summary", value:'The remote ComfortableMexicanSofa CMS Engine
 is prone to a default account authentication bypass vulnerability.');

  script_tag(name:"impact", value:'This issue may be exploited by a remote attacker to gain
 access to sensitive information.');

  script_tag(name:"vuldetect", value:'Try to login with default credentials.');
  script_tag(name:"insight", value:'It was possible to login with default credentials "username/password"');
  script_tag(name:"solution", value:'Change the password.');

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

foreach adminDir ( make_list( "/admin", "/cms-admin" ) ) {

  url = dir + adminDir + "/sites/new";
  req = http_get( item: url, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  useragent = http_get_user_agent();
  if( res && res =~ "^HTTP/1\.[01] 401") {

    auth = base64( str:'username:password' );

    host = http_host_name( port:port );

    req = 'GET ' + url + ' HTTP/1.1\r\n' +
          'Host: ' + host + '\r\n' +
          'User-Agent: ' + useragent + '\r\n' +
          'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
          'Accept-Language: en-US,en;q=0.5\r\n' +
          'Authorization: Basic ' + auth + '\r\n' +
          '\r\n';
    res = http_keepalive_send_recv( port:port, data:req );

    if( "<title>ComfortableMexicanSofa CMS Engine</title>" >< res || "<h2>New Site</h2>" >< res ) {

      report = report_vuln_url( port:port, url:url );
      report = report + '\n\nIt was possible to login using the following credentials:\n\nusername:password\n';

      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
