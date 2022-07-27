###############################################################################
# OpenVAS Vulnerability Test
# $Id: famd_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# famd detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18186");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("famd detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_require_ports("Services/unknown");
  script_dependencies("find_service2.nasl");

  script_tag(name:"summary", value:"A system related service which does not need to be reachable from the network
is listening on the remote port.

Description :

The File Alteration Monitor daemon is running on this port. This service does not need to be reachable from the
outside, it is therefore recommended that reconfigure it to disable network access.");

  script_tag(name:"solution", value:"Start famd with the -L option or edit /etc/fam.conf and set the option
'local_only' to 'true' and restartd the famd service.

Alternatively, you may wish to filter incoming traffic to this port.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("network_func.inc");

# :::FAMD
# 00: 00 00 00 10 2f 74 6d 70 2f 2e 66 61 6d 52 48 61    ..../tmp/.famRHa
# 10: 46 4c 4c 00                                        FLL.

a = get_host_ip();
# Do not use islocalhost, famd is supposed to be listening on 127.0.0.1
# only, not an external interface
local = (a =~ "^0*127\.[0-9]+\.[0-9]+\.[0-9]+$");
lan = local || is_private_addr(addr: a);

port = get_unknown_port( nodefault:TRUE ); #famd runs on any free privileged port??

s = open_sock_tcp(port);
if (! s) exit(0);

send(socket: s, data: '\0\0\0\x1aN0 500 500 sockmeister\00\x0a\0');
b = recv(socket: s, length: 512);
close(s);

if (isnull(b) || substr(b, 0, 2) != '\0\0\0') exit(0);

# First test triggers against HP Openview or Tibco
l = strlen(b);
if( l < 5) exit( 0 );
if (b[l-1] != '\0' || ord(b[3]) != l - 4 || ord(b[4]) != '/' ) exit(0);

register_service(port: port, ipproto: 'tcp', proto: 'famd');

r = 'The File Alteration Monitor daemon is running on this port\n';

if (local)
  log_message(port: port, data: r + '.\n');
else {
 r += ' and does not need to be reachable from the outside.\n';

 if (!lan)
  r += 'Exposing it on Internet is definitely not a good idea.\n';

 r += '\nSolution : to restrict it to the loopback interface,
run it with -L or set "local_only = false" in /etc/fam.conf';
 log_message(port: port, data: r);
 exit(0);
}

exit(0);