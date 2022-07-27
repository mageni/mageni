###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siemens_scalance_default_web_credential.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# Siemens Scalance Default Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
CPE = 'cpe:/h:siemens:scalance';

if (description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.103723");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-05-30 16:44:04 +0200 (Thu, 30 May 2013)");
  script_name("Siemens Scalance Default Credentials");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_siemens_scalance_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("siemens_scalance/installed");
  script_tag(name:"solution", value:"Change the password.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"summary", value:"The remote Siemens Scalance is prone to a default account authentication bypass
vulnerability. This issue may be exploited by a remote attacker to
gain access to sensitive information or modify system configuration.

It was possible to login as user 'admin' with password 'admin'.");
  exit(0);
}

include("http_func.inc");

include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

url = "/";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("nonceA" >!< buf)exit(0);

noncea = eregmatch(pattern:'<input type="hidden" name="nonceA" value="([^"]+)">', string:buf);
if(isnull(noncea[1]))exit(0);

cookie = eregmatch(pattern:'Set-Cookie: siemens_ad_session=([^;]+);', string:buf);
if(isnull(cookie[1]))exit(0);

co = cookie[1];

host = get_host_name();

na   = noncea[1];
user = "admin";
pass = "admin";

login = 'encoded=' + user + "%3A" + hexstr(MD5(user + ":" + pass + ":" + na));
login += '&nonceA=' + na;

len = strlen(login);

req = string("POST / HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Accept-Encoding: identity\r\n",
             "DNT: 1\r\n",
             "Connection: close\r\n",
             "Referer: http://",host,"/\r\n",
             "Cookie: siemens_ad_session=",co,"\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             login);

result = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Login Successful" >< result) {

  security_message(port:port);
  exit(0);

}

exit(0);
