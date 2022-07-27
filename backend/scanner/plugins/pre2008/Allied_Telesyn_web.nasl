# OpenVAS Vulnerability Test
# $Id: Allied_Telesyn_web.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Allied Telesyn Router/Switch Web interface found with default password
#
# Authors:
# Charles Thier <cthier@thethiers.net>
# This script was based off of Renaud Deraison's script
# 11522 Linksys Router default password script.
#
# Copyright:
# Copyright (C) 2005 Charles Thier
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18413");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("Allied Telesyn Router/Switch Web interface found with default password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2005 Charles Thier");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("ATR-HTTP/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Connect to this Router/Switch and change the default password.");

  script_tag(name:"summary", value:"The Allied Telesyn Router/Switch has the default password set.");

  script_tag(name:"impact", value:"The attacker could use this default password to gain remote access
  to the switch or router. This password could also be potentially used to gain other sensitive
  information about your network from the device.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
banner = get_http_banner (port:port);
if(!banner || "Server: ATR-HTTP-Server" >!< banner)
  exit(0);

url = "/";
res = http_get_cache(item:url, port:port);
if(!res)
  exit(0);

if( egrep( pattern:"^HTTP/1\.[01] 401", string:res ) ) {

  # nb: Just for the request below
  req = http_get(item:url, port:port);
  req -= string("\r\n\r\n");
  # nb: Credentials manager:friend
  req += string("\r\nAuthorization: Basic bWFuYWdlcjpmcmllbmQ=\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    exit(0);

  if( egrep( pattern:"^HTTP/1\.[01] 200", string:res) ) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);