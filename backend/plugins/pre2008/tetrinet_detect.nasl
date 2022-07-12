# OpenVAS Vulnerability Test
# $Id: tetrinet_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
# Description: Tetrinet server detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.19608");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Tetrinet server detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");

  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_require_ports("Services/unknown", 31457);
  script_dependencies("find_service.nasl", "find_service2.nasl");

  script_tag(name:"solution", value:"If this service is not needed, disable it or filter incoming
traffic to this port.");

  script_tag(name:"summary", value:"A game server has been detected on the remote host.


Description :

The remote host runs a Tetrinet game server on this port. Make
sure the use of this software is done in accordance to your
security policy.");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

c = '00469F2CAA22A72F9BC80DB3E766E7286C968E8B8FF212\xff';

port = get_unknown_port( default:31457 );

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data:c);
b = recv(socket: s, length: 1024);
if ( ! b ) exit(0);
if (match(string: b, pattern: 'winlist *'))
{
 log_message(port: port);
 register_service(port: port, proto: 'tetrinet');
}
