###############################################################################
# OpenVAS Vulnerability Test
# $Id: napster_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Detect the presence of Napster
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2000 by Noam Rathaus <noamr@securiteam.com>, Beyond Security Ltd.
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10344");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Detect the presence of Napster");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Beyond Security");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/napster", 6699);

  script_tag(name:"solution", value:"Filter this port if you do not want your network
  users to exchange MP3 files or if you fear that Napster may be used to transfer any non-mp3 file");

  script_tag(name:"summary", value:"Napster is running on a remote computer.

  Napster is used to share MP3 across the network, and can be misused (by modifying the three first bytes
  of a target file) to transfer any file off a remote site.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

uk = 0;
port = get_kb_item("Services/napster");
if(!port){
  port = 6699;
  uk = 1;
}

if(!get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if(!soc) exit(0);

res = recv(socket:soc, length:50);
if("1" >< res){

  data = string("GET\r\n");
  send(socket:soc, data:data);
  res = recv(socket:soc, length:50);
  if(!res){

    data = string("GET /\r\n");
    send(socket:soc, data:data);
    res = recv(socket:soc, length:150);

    if("FILE NOT SHARED" >< res){
      security_message(port:port);
      if(uk)register_service(proto:"napster", port:port);
    }
  }
}

close(soc);