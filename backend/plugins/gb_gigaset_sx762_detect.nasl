###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gigaset_sx762_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Gigaset SX762 Detection
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

if (description)
{

  script_oid("1.3.6.1.4.1.25623.1.0.103729");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-06-05 13:20:54 +0200 (Wed, 05 Jun 2013)");
  script_name("Gigaset SX762 Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("SiemensGigaset-Server/banner");

  script_tag(name:"summary", value:"Detection of Gigaset SX762.

The script sends a connection request to the server and attempts to
determine if the remote host is a Gigaset SX762 from the reply.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("host_details.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if(!banner || "Server: SiemensGigaset-Server" >!< banner)exit(0);

url = "/UE/welcome_login.html";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Gigaset sx762" >< buf) {

  set_kb_item(name:"gigaset_sx762/installed",value:TRUE);
  cpe = 'cpe:/a:siemens:gigaset:sx762';

  register_product(cpe:cpe, location:port + "/tcp", port:port);

  log_message(data:"The remote Host is a Siemens Gigaset sx762 device.\nCPE: " + cpe + "\n", port:port);
  exit(0);

}

exit(0);
