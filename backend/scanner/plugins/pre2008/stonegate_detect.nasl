# OpenVAS Vulnerability Test
# $Id: stonegate_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: StoneGate client authentication detection
#
# Authors:
# Holger Heimann <hh@it-sec.de>
#
# Copyright:
# Copyright (C) 2003 it.sec/Holger Heimann
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
  script_oid("1.3.6.1.4.1.25623.1.0.11762");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("StoneGate client authentication detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 it.sec/Holger Heimann");
  script_family("Firewalls");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/SG_ClientAuth", 2543);

  script_tag(name:"solution", value:"Restrict incoming traffic to this port");

  script_tag(name:"summary", value:"A StoneGate firewall login is displayed.

  If you see this from the internet or an not administrative
  internal network it is probably wrong.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");

## Heres the real dialog:
#
#	 telnet www.xxxxxx.de 2543
#	Trying xxx.xxx.xxx.xxx ...
#	Connected to www.xxxxs.de.
#	Escape character is '^]'.
#	StoneGate firewall (xx.xx.xx.xx)
#	SG login:

port = get_port_for_service(default:2543, proto:"SG_ClientAuth");

banner = get_kb_item("FindService/tcp/" + port + "/spontaneous");
if(!banner)
  exit(0);

r = egrep(pattern:"(StoneGate firewall|SG login:)", string:banner);
if(!r)
  exit(0);

report = "A StoneGate firewall client authentication login is displayed.

Here is the banner :

" + r;

log_message(port:port, data:report);
exit(0);