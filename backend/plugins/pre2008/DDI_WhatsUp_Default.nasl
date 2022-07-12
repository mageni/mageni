# OpenVAS Vulnerability Test
# $Id: DDI_WhatsUp_Default.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WhatsUp Gold Default Admin Account
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2001 H D Moore <hdmoore@digitaldefense.net>
# Copyright (C) 2001 Digital Defense Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.11004");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("WhatsUp Gold Default Admin Account");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Login to this system and either disable the admin
  account or assign it a difficult to guess password.");

  script_tag(name:"summary", value:"This WhatsUp Gold server still has the default password for
  the admin user account. An attacker can use this account to probe other systems on the network
  and obtain sensitive information about the monitored systems.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
buf = http_get_cache( item:"/", port:port );
if(! buf || buf !~ "^HTTP/1\.[01] 401" )
  exit(0);

req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4K\r\n\r\n");
res = http_send_recv(port:port, data:req);
if("Whatsup Gold" >< buf && "Unauthorized User" >!< buf) {
  security_message(port:port);
  exit(0);
}

exit(99);