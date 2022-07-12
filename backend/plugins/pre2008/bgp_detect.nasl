###############################################################################
# OpenVAS Vulnerability Test
# $Id: bgp_detect.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# BGP detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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

# See RFC 1771

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11907");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("BGP detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports(179);

  script_tag(name:"solution", value:"If the remote service is not used, disable it.
  Make sure that access to this service is either filtered so that only
  allowed hosts can connect to it, or that TCP MD5 is enabled to protect
  this service from rogue connections.");

  script_tag(name:"summary", value:"The remote host is running a BGP (Border Gatway Protocol) service.

  Description :

  The remote host is running BGP, a popular routing protocol. This indicates
  that the remote host is probably a network router.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
##include("dump.inc");
include("misc_func.inc");

port = 179;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

s = this_host();
v = eregmatch(pattern: "^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9])+$", string: s);
if (isnull(v)) exit(0);
for (i = 1; i <=4; i++) a[i] = int(v[i]);

r = '\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'; # Marker
r += raw_string(0, 45,	# Length
		1,	# Open message
		4, 	# Version
		rand() % 256, rand() % 256,	# My AS
		0, 180,	# Hold time
		a[1], a[2], a[3], a[4],	# BGP identifier
		0, 	# Optional parameter length
		2, 6, 1, 4, 0, 1, 0, 1,
		2, 2, 80, 0,
		2, 2, 2, 0	);

send(socket: soc, data: r);

r = recv(socket: soc, length: 16, min: 16);
if( strlen( r ) < 16 ) exit( 0 );

for (i = 0; i < 16; i ++)
  if (ord(r[i]) != 0xFF)
    break;
if (i < 16) exit(0);		# Bad marker

r = recv(socket: soc, length: 2, min: 2);
len = ord(r[0]) * 256 + ord(r[1]);
len -= 18;
if (len <= 0) exit(0);
r = recv(socket: soc, length: len, min: len);
##dump(ddata: r, dtitle: "BGP");
type = ord(r[0]);

if (type == 1)	# Hello
{
  ver = ord(r[1]);
  as = 256 * ord(r[2]) + ord(r[3]);
  ht = 256 * ord(r[4]) + ord(r[5]);	# Hold time
}
#else if (type == 3)	# Notification - may be error

register_service(port: port, proto: "bgp");
log_message(port);