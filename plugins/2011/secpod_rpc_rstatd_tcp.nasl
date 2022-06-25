###############################################################################
# OpenVAS Vulnerability Test
#
# RPC rstatd Service Detection (TCP)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.901206");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  #Remark: NIST don't see "configuration issues" as software flaws so this CVSS has a value of 0.0.
  #However we still should report such a configuration issue with a criticality so this has been commented
  #out to avoid that the automatic CVSS score correction is setting the CVSS back to 0.0
  #  script_cve_id("CVE-1999-0624");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("RPC rstatd Service Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Useless services");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  script_require_keys("rpc/portmap/tcp/detected");

  script_xref(name:"URL", value:"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-1999-0624");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/115");
  script_xref(name:"URL", value:"http://en.wikipedia.org/wiki/Remote_procedure_call");
  script_xref(name:"URL", value:"http://www.iss.net/security_center/advice/Services/SunRPC/rpc.rstatd/default.htm");

  script_tag(name:"solution", value:"Disable the RPC rstatd service if not needed.");

  script_tag(name:"summary", value:"This remote host is running a RPC rstatd service via TCP.");

  script_tag(name:"insight", value:"The rstatd service is a RPC server which provides remotely monitorable statistics
  obtained from the kernel such as,

  - system uptime

  - cpu usage

  - disk usage

  - network usage

  - load averages

  - and more.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

# nb: RPC rstatd Program ID
RPC_PROG = 100001;

port = get_rpc_port( program:RPC_PROG, protocol:IPPROTO_TCP );
if( ! port )
  exit( 0 );

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

rpc_paket = construct_rpc_packet( program:RPC_PROG, prog_ver:3, procedure:1, data:NULL, udp:"tcp" );

send( socket:soc, data:rpc_paket );
res = recv( socket:soc, length:4096 );
close( soc );

# nb: It's not a proper response if response length < 100 and > 130
if( strlen( res ) < 100 || strlen( res ) > 150 )
  exit( 0 );

# nb: Accept state position (UDP: 20, TCP: 20 + 4 bytes of Fragment header)
pos = 20 + 4;

if( ord( res[pos] ) == 0 && ord( res[pos+1] ) == 0 &&
    ord( res[pos+2] ) == 0 && ord( res[pos+3] ) == 0 ) {
  # nb: We don't use register_service as this is already done by rpcinfo.nasl
  security_message( port:port );
}

exit( 0 );