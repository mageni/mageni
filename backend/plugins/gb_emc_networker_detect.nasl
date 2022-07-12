###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_networker_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# EMC Networker Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

  script_oid("1.3.6.1.4.1.25623.1.0.103123");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-23 13:28:27 +0100 (Wed, 23 Mar 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("EMC Networker Detection");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports(7938);
  script_tag(name:"summary", value:"This host is running EMC Networker, a centralized, automated backup solution.");
  script_xref(name:"URL", value:"http://www.emc.com/products/detail/software/networker.htm");
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");

SCRIPT_DESC = "EMC Networker Detection";

port = 7938;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

req =  raw_string(0x80,0,0,0x38,rand()%256,rand()%256,rand()%256,rand()%256,0x00,0x00,0x00,0x00,
                  0x00,0x00,0x00,0x02,0x00,0x01,0x86,0xA0,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x03,
                  0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                  0x01,0x05,0xf3,0xe1,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x00);

send(socket: soc, data: req);
buf = recv(socket: soc,length:32);

if(strlen(buf) != 32 || ord(buf[0]) != 128)exit(0);

if (hexstr(buf) =~ "^8000001c") {

  set_kb_item (name:"emc_networker/port", value:port);
  register_host_detail(name:"App", value:string("cpe:/a:emc:networker"), desc:SCRIPT_DESC);
  register_service(port: port, proto: "emc_networker");
  log_message(port:port);
  exit(0);

}

exit(0);
