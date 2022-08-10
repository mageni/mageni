# OpenVAS Vulnerability Test
# $Id: webcalendar_info_disclosure.nasl 14240 2019-03-17 15:50:45Z cfischer $
# Description: WebCalendar User Account Enumeration Disclosure Issue
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.80021");
  script_version("$Revision: 14240 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-17 16:50:45 +0100 (Sun, 17 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(17853);
  script_cve_id("CVE-2006-2247");
  script_name("WebCalendar User Account Enumeration Disclosure Issue");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2006 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("webcalendar_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("webcalendar/installed");

  script_tag(name:"summary", value:"The version of WebCalendar on the remote host is prone to a user
  account enumeration weakness in that in response to login attempts it returns different error messages
  depending on whether the user exists or the password is invalid.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to WebCalendar 1.0.4 or later.");

  script_xref(name:"URL", value:"http://sourceforge.net/project/shownotes.php?group_id=3870&release_id=423010");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
install = get_kb_item(string("www/", port, "/webcalendar"));
if (isnull(install)) exit(0);

host = http_host_name(port:port);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {

  dir = matches[2];
  url = string(dir, "/login.php");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if (!res)
    exit(0);

  if ("webcalendar_session=deleted; expires" >< res && '<input name="login" id="user"' >< res)
  {
    postdata=string( "login=vt-test", unixtime(), "&", "password=vt-test" );
    req = string("POST ", url, " HTTP/1.1\r\n",
                 "Host: ", host, "\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: ", strlen(postdata), "\r\n",
                 "\r\n",
                 postdata );

    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (!res)
      exit(0);

    if ("Invalid login: no such user" >< res) {
      security_message(port);
    }
  }
}
