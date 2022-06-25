# OpenVAS Vulnerability Test
# $Id: nortel_webadmin.nasl 13660 2019-02-14 09:48:45Z cfischer $
# Description: Nortel Web Management Default Username and Password (ro/ro)
#
# Authors:
# Noam Rathaus <noamr@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.15716");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Nortel Web Management Default Username and Password (ro/ro)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Set a strong password for this account or disable it.");

  script_tag(name:"summary", value:"It is possible to access the remote network device's web management console
  by providing it with a its default username and password (ro/ro). This username
  can be also used when accessing the device via SSH, telnet, rlogin, etc.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
res = http_get_cache(item:"/", port:port);
if(!res)
  exit(0);

# Sample response:
#
#<input type="hidden" name="encoded">
#<input type="hidden" name="nonce" value="
#0a7731a40000002a
#">
#<input type="submit" name="goto" value="Log On" onClick="encode()">

nonce = strstr(res, string('<input type="hidden" name="nonce" value="'));
nonce = strstr(nonce, string("\r\n"));
nonce -= string("\r\n");
nonce = nonce - strstr(nonce, string("\r\n"));
if(nonce)
{
  useragent = http_get_user_agent();
  host = http_host_name( port:port );
  pre_md5 = string("ro:ro:", nonce);
  md5 = hexstr(MD5(pre_md5));

  req = string("POST / HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n",
               "Accept-Language: en-us,en;q=0.5\r\n",
               "Accept-Encoding: gzip,deflate\r\n",
               "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
               "Connection: close\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ");
  content = string("encoded=ro%3A", md5, "&nonce=", nonce, "&goto=Log+On&URL=%2F");

  req = string(req, strlen(content), "\r\n\r\n",
               content);
  res2 = http_keepalive_send_recv(port:port, data:req, bodyonly:0);
  if(!res2)
    exit(0);

  if ((res2 >< "Set-Cookie: auth=") && (res2 >< "logo.html")) {
    report = report_vuln_url(port:port, url:"/");
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);