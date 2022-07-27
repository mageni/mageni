# OpenVAS Vulnerability Test
# $Id: DDI_F5_Default_Support.nasl 13685 2019-02-15 10:06:52Z cfischer $
# Description: F5 Device Default Support Password
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
# Copyright (C) 2001 H D Moore <hdmoore@digitaldefense.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.10820");
  script_version("$Revision: 13685 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 11:06:52 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0508");
  script_name("F5 Device Default Support Password");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Remove the support account entirely or
  change the password of this account to something that is difficult to guess.");

  script_tag(name:"summary", value:"This F5 Networks system still has the default
  password set for the support user account. This account normally provides read/write
  access to the web configuration utility.");

  script_tag(name:"impact", value:"An attacker could take advantage of this to reconfigure
  your systems and possibly gain shell access to the system with super-user privileges.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:443);

req = string("GET /bigipgui/bigconf.cgi?command=bigcommand&CommandType=bigpipe HTTP/1.0\r\nAuthorization: Basic c3VwcG9ydDpzdXBwb3J0\r\n\r\n");
buf = http_send_recv(port:port, data:req);

if (("/bigipgui/" >< buf) && ("System Command" >< buf)) {
  security_message(port:port);
  http_set_is_marked_embedded(port:port);
}