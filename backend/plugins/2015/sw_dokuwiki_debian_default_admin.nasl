###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_dokuwiki_debian_default_admin.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Dokuwiki default admin credentials on Debian
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:dokuwiki:dokuwiki';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111044");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-30 09:00:00 +0100 (Fri, 30 Oct 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Dokuwiki default admin credentials on Debian");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_tag(name:"summary", value:"Detection of Dokuwiki default admin credentials on Debian.");
  script_tag(name:"vuldetect", value:"Check if it is possible to login with default admin credentials.");
  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information.");
  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/fix-your-debconf-settings

  This default credentials are created if Dokuwiki is installed on Debian with debconf configured to skip high priority questions.");
  script_tag(name:"solution", value:"Change the password of the 'admin' account.");

  script_xref(name:"URL", value:"https://www.dokuwiki.org/");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/doku.php?id=start&do=login";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

cookie1 = eregmatch( pattern:"DokuWiki=([0-9a-z]+);", string:res );
if( isnull( cookie1[1] ) ) exit( 0 );

sectok = eregmatch( pattern:"sectok=([0-9a-z]+)", string:res );
if( isnull( sectok[1] ) ) exit( 0 );

host = http_host_name( port:port );

url = dir + "/doku.php?id=start&do=login&sectok=" + sectok[1];
useragent = http_get_user_agent();
data = "sectok=" + sectok[1] + "&id=start&do=login&u=admin&p=fix-your-debconf-settings";
len = strlen( data );

req = 'POST ' + url + ' HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Referer: http://' + host + url + '\r\n' +
      'Cookie: DokuWiki=' + cookie1[1] + '\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' +
      data;

res = http_keepalive_send_recv( port:port, data:req );

cookie2 = eregmatch( pattern:"DW([0-9a-z]+)=([0-9a-zA-Z%]+);", string:res );
if( isnull( cookie2[1] ) ) exit( 0 );

req = 'GET ' + dir + '/doku.php?id=start HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Referer: http://' + host + url + '\r\n' +
      'Cookie: DokuWiki=' + cookie1[1] + '; DW' + cookie2[1] + '=' + cookie2[2] + '\r\n' +
      '\r\n';

res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "do=admin" >< res && "action admin" >< res ) {

  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
