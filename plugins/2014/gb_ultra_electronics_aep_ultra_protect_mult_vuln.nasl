###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultra_electronics_aep_ultra_protect_mult_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# Ultra Electronics AEP Ultra Protect Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.804491");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-10-14 17:03:16 +0530 (Tue, 14 Oct 2014)");

  script_name("Ultra Electronics AEP Ultra Protect Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Ultra Electronics AEP
  Ultra Protect and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read information or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - The /preauth/login.cgi script not properly sanitizing user-supplied input
    to the 'realm' GET parameter.

  - The /preauth/login.cgi not properly sanitizing user input, specifically
    path traversal style attacks (e.g. '../') supplied via the 'realm' GET
    parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to inject or manipulate SQL queries in the back-end database, allowing for
  the manipulation or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Ultra Electronics - Series A
  Version 7.2.0.19 and 7.4.0.7");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/34918");
  script_xref(name:"URL", value:"http://www.osisecurity.com.au/advisories/ultra-aep-netilla-vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 443);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


http_port = get_http_port(default:443);

sndReq = http_get(item:"/preauth/login.cgi", port:http_port);
rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

if("/preauth/styles.css" >< rcvRes)
{
  url = "/preauth/login.cgi?realm=../../../../bin/";

  sndReq = http_get(item:url, port:http_port);
  rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

  if("<title>Error</title>" >< rcvRes && ">mkdir" >< rcvRes
     && ": Permission denied at" >< rcvRes )
  {
    security_message(port:http_port);
    exit(0);
  }
}

exit(99);
