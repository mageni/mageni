# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901206");
  script_version("2021-10-20T09:17:04+0000");
  script_tag(name:"last_modification", value:"2021-10-20 10:23:51 +0000 (Wed, 20 Oct 2021)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-1999-0624");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RPC rstatd Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Useless services");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  script_mandatory_keys("rpc/portmap/tcp/detected");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/115");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/advice/Services/SunRPC/rpc.rstatd/default.htm");

  script_tag(name:"solution", value:"Disable the RPC rstatd service if not needed.");

  script_tag(name:"summary", value:"This remote host is running a RPC rstatd service via TCP.");

  script_tag(name:"insight", value:"The rstatd service is a RPC server which provides remotely
  monitorable statistics obtained from the kernel such as,

  - system uptime

  - cpu usage

  - disk usage

  - network usage

  - load averages

  - and more.

  Remark: NIST don't see 'configuration issues' as software flaws so the referenced CVE has a
  severity of 0.0. The severity of this VT has been raised by Greenbone to still report a
  configuration issue on the target.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("rpc.inc");
include("byte_func.inc");

# nb: RPC rstatd Program ID
RPC_PROG = 100001;

port = rpc_get_port( program:RPC_PROG, protocol:IPPROTO_TCP );
if( ! port )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

rpc_paket = rpc_construct_packet( program:RPC_PROG, prog_ver:3, procedure:1, data:NULL, udp:"tcp" );

send( socket:soc, data:rpc_paket );
res = recv( socket:soc, length:4096 );
close( soc );

# nb: It's not a proper response if response length < 100 and > 130
if( strlen( res ) < 100 || strlen( res ) > 150 )
  exit( 0 );

# nb: Accept state position (UDP: 20, TCP: 20 + 4 bytes of Fragment header)
pos = 20 + 4;

if( ord( res[pos] ) == 0 && ord( res[pos + 1] ) == 0 &&
    ord( res[pos + 2] ) == 0 && ord( res[pos + 3] ) == 0 ) {
  # nb: We don't use register_service as this is already done by rpcinfo.nasl
  security_message( port:port );
  exit( 0 );
}

exit( 99 );