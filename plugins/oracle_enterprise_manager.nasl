# OpenVAS Vulnerability Test
# Description: Oracle Enterprise Manager
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.17586");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-05-05T09:44:01+0000");
  script_tag(name:"last_modification", value:"2020-05-06 11:41:12 +0000 (Wed, 06 May 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Oracle Enterprise Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 5500, 1158);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Oracle Enterprise Manager

  The script sends a connection request to the server and attempts to
  detect Oracle Enterprise Manager from the reply.");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = http_get_port(default:1158);

url = "/em/console/logon/logon";
req = http_get(item:url, port:port);
rep = http_keepalive_send_recv(port:port, data:req);
if(!rep)
  exit(0);

if("<title>Oracle Enterprise Manager</title>" >< rep) {

  set_kb_item(name:string("www/", port, "/oracle_enterprise_manager"), value:string("unknown under ", url));
  set_kb_item(name:"oracle_enterprise_manager/installed", value:TRUE);

  cpe = "cpe:/a:oracle:enterprise_manager";
  register_product(cpe:cpe, location:url, port:port, service:"www");

  log_message(data:build_detection_report(app:"Oracle Enterprise Manager", version:"unknown", install:url, cpe:cpe, concluded:"<title>Oracle Enterprise Manager</title>"),
              port:port);
}

exit(0);
