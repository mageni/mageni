# OpenVAS Vulnerability Test
# $Id: packeteer_web_login.nasl 14328 2019-03-19 13:54:40Z cfischer $
# Description: Packeteer Web Management Interface Login
#
# Authors:
# nnposter
#
# Copyright:
# Copyright (C) 2006-2007 nnposter
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
  script_oid("1.3.6.1.4.1.25623.1.0.80032");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 14328 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:54:40 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Packeteer Web Management Interface Login");
  script_family("Web application abuses");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (c) 2006-2007 nnposter");
  script_dependencies("logins.nasl", "packeteer_web_detect.nasl");
  script_mandatory_keys("bluecoat_packetshaper/installed", "http/password");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"It is possible to log onto the remote web application.

  The scanner was able to log onto the remote Packeteer web management
  interface with the given credentials and has stored the authentication
  cookie in the KB for use with other plugins.");
  exit(0);
}

# Notes:
# - logins.nasl will not process the HTTP password preference if the HTTP
#   username is left blank. To compensate for this behavior this script assumes
#   that a username that consists of a single non-alphanumeric character is not
#   really meant to be used.
# - Does not work with http_keepalive_send_recv() for some reason.
#   Resorting to http_send_recv()


include("http_func.inc");
#include("http_keepalive.inc");

if (!get_kb_item("bluecoat_packetshaper/installed")) exit(0);
if (!get_kb_item("http/password")) exit(0);

function hex2str()
{
local_var xlat,hs,s,i,j;
hs=_FCT_ANON_ARGS[0];
s=""; # nb: To make openvas-nasl-lint happy...
for (i=0; i<256; ++i) xlat[substr(hex(i),2)]=raw_string(i);
for (j=0; j<strlen(hs)/2; ++j) s+=xlat[substr(hs,2*j,2*j+1)];
return s;
}

port=get_http_port(default:80);
if (!get_tcp_port_state(port) || !get_kb_item("www/"+port+"/packeteer")) exit(0);

#resp=http_keepalive_send_recv(port:port,data:http_get(item:"/login.htm",port:port));
resp=http_send_recv(port:port,data:http_get(item:"/login.htm",port:port));
if (!resp) exit(0);

match=eregmatch(
    pattern:'challenge *= *"([0-9A-Fa-f]{32})".{1,80}chapID *= *"([0-9]*)"',
    string:resp);
challenge=match[1];
chapid=match[2];
if (!challenge || !chapid) exit(0);

authsrc=raw_string(int(chapid))
    +get_kb_item("http/password")
    +hex2str(challenge);
response=hexstr(MD5(authsrc));

username=get_kb_item("http/login");
if (!strlen(username) || username=~"^[^a-z0-9]$") username="";

url="/Login?"
    + "LOGIN.CHALLENGE="+challenge
    +"&LOGIN.CHAPID="+chapid
    +"&LOGIN.RESPONSE="+response
    +"&LOGIN.USERNAME="+username;

#resp=http_keepalive_send_recv(port:port,data:http_get(item:url,port:port));
resp=http_send_recv(port:port,data:http_get(item:url,port:port));
if (!resp) exit(0);

cookie=egrep(pattern:"^Set-Cookie: *[^a-z0-9]PSpcV310=[0-9a-f]{32}",
             string:resp,
             icase:TRUE);
if (!cookie) exit(0);
cookie=ereg_replace(string:cookie,pattern:"^Set-",replace:"",icase:TRUE);

set_kb_item(name:"/tmp/http/auth/"+port,value:cookie);
