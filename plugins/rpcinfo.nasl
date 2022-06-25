###############################################################################
# OpenVAS Vulnerability Test
# $Id: rpcinfo.nasl 13541 2019-02-08 13:21:52Z cfischer $
#
# Obtain list of all port mapper registered programs via RPC
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11111");
  script_version("$Revision: 13541 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 14:21:52 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Obtain list of all port mapper registered programs via RPC");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap_tcp.nasl");
  # nb: This could run even before find_service.nasl to avoid that find_service.nasl
  # is thrown against those services / ports it can't detect anyway.
  script_mandatory_keys("rpc/portmap");

  script_tag(name:"summary", value:"This script calls the DUMP RPC on the port mapper, to obtain the
  list of all registered programs.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

# If the portmapper is not installed, then just exit
portmap = get_kb_item( "rpc/portmap" );
if( ! portmap ) exit( 0 );
if( ! get_port_state( portmap ) ) exit( 0 );
soc = open_sock_tcp( portmap ); # TODO: Won't work if the port is only available via UDP...
if( ! soc ) exit( 0 );

report_tcp = make_list();
report_udp = make_list();

# RPC Names, from Linux /etc/rpc

rpc_names="
portmapper	100000	portmap sunrpc rpcbind
rstatd		100001	rstat rup perfmeter rstat_svc
rusersd		100002	rusers
nfs		100003	nfsprog
ypserv		100004	ypprog
mountd		100005	mount showmount
ypbind		100007
walld		100008	rwall shutdown
yppasswdd	100009	yppasswd
etherstatd	100010	etherstat
rquotad		100011	rquotaprog quota rquota
sprayd		100012	spray
3270_mapper	100013
rje_mapper	100014
selection_svc	100015	selnsvc
database_svc	100016
rexd		100017	rex
alis		100018
sched		100019
llockmgr	100020
nlockmgr	100021
x25.inr		100022
statmon		100023
status		100024
bootparam	100026
ypupdated	100028	ypupdate
keyserv		100029	keyserver
sunlink_mapper	100033
tfsd		100037
nsed		100038
nsemntd		100039
showfhd		100043	showfh
ioadmd		100055	rpc.ioadmd
NETlicense	100062
sunisamd	100065
debug_svc 	100066  dbsrv
ypxfrd		100069  rpc.ypxfrd
bugtraqd	100071
kerbd		100078
event		100101	na.event	# SunNet Manager
logger		100102	na.logger	# SunNet Manager
sync		100104	na.sync
hostperf	100107	na.hostperf
activity	100109	na.activity	# SunNet Manager
hostmem		100112	na.hostmem
sample		100113	na.sample
x25		100114	na.x25
ping		100115	na.ping
rpcnfs		100116	na.rpcnfs
hostif		100117	na.hostif
etherif		100118	na.etherif
iproutes	100120	na.iproutes
layers		100121	na.layers
snmp		100122	na.snmp snmp-cmc snmp-synoptics snmp-unisys snmp-utk
traffic		100123	na.traffic
nfs_acl		100227
sadmind		100232
nisd		100300	rpc.nisd
nispasswd	100303	rpc.nispasswdd
ufsd		100233	ufsd
pcnfsd		150001	pcnfs
amd		300019  amq
# Legato NetWorker
nsrd		390103	nsr	 # NetWorker service
nsrmmd		390104	nsrmm	 # NetWorker media mupltiplexor daemon
nsrindexd	390105	nsrindex # NetWorker file index daemon
nsrmmdbd	390107	nsrmmdb  # NetWorker media management database daemon
nsrjb		390110	nsrjbd	 # NetWorker jukebox-control service
nsrexec		390113	nsrexecd # NetWorker client execution service
nsrnotd		390400		 # NetWorker notary service
#
sgi_fam		391002	fam
netinfobind	200100001
bwnfsd		545580417
fypxfrd		600100069 freebsd-ypxfrd
";

i=0;

# A big thanks to Ethereal!

xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;

pack =
raw_string(	0x80, 0, 0, 0x28,	# Last fragment; fragment length = 40
		xid1, xid2, xid3, xid4,	# XID
		0, 0, 0, 0,		# Call
		0, 0, 0, 2,		# RPC version = 2
		0, 1, 0x86, 0xA0,	# Program = portmapper (10000)
		0, 0, 0, 2,		# Program version = 2
		0, 0, 0, 4,		# Procedure = 4
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0	# Null verifier
	);

send(socket: soc, data: pack);

r = recv(socket: soc, length: 4, min: 4);
if(strlen(r) < 4)exit(0);

last_frag = r[0];
y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
#display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
# First 4 bytes are XID
r = recv(socket: soc, length: 4, min: 4);

# Reply?
r = recv(socket: soc, length: 4, min: 4);
y =ord(r[0])*256; y=y+ord(r[1]); y=y*256; y=y+ord(r[2]); y=y*256;y=y+ord(r[3]);

# Accepted?
r = recv(socket: soc, length: 4, min: 4);
a =ord(r[0])*256; a=a+ord(r[1]); a=a*256; a=a+ord(r[2]); a=a*256;a=a+ord(r[3]);

# Next 8 bytes are verifier
r = recv(socket: soc, length: 8, min: 8);

# Next four is execution status
r = recv(socket: soc, length: 4, min: 4);
z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);

#display("Reply=", y, "\nAccepted=", a,"\nExec=", z, "\n");

# Reply (1) && accepted (0) && executed successfully (0)
if ((y != 1) || (a != 0) || (z != 0))
{
  close(soc);
  exit(0);
}

# Value follow?
r = recv(socket: soc, length: 4, min: 4);
vf =ord(r[0])*256; vf=vf+ord(r[1]); vf=vf*256; vf=vf+ord(r[2]); vf=vf*256;vf=vf+ord(r[3]);
len = 28;
while (vf)
{
  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }
  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  program = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  version = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  proto = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len=len+4;
  z =ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  port = z;

  if (len >= frag_len)
  {
    r = recv(socket: soc, length: 4, min: 4);
    last_frag = ord(r[0]);
    y = ord(r[2]) * 256; frag_len = y + ord(r[3]);
    #display("last_frag=", last_frag, " - frag_len=", frag_len, "\n");
    len=0;
  }

  r = recv(socket: soc, length: 4, min: 4); len = len+4;
  z = ord(r[0])*256; z=z+ord(r[1]); z=z*256; z=z+ord(r[2]); z=z*256;z=z+ord(r[3]);
  vf = z;

  # Running get_port_state is not a great idea: we miss some registered RPC.
  #if ((proto == 17 ) || get_port_state(port))
  {
    req = string("^[a-zA-Z0-9_-]+[ \t]+", program);
    str = egrep(string:rpc_names, pattern: req);
    name = ereg_replace(string: str,
		pattern: string("^([a-zA-Z0-9_-]+)[ \t]+.*"),
		replace: "\1");
    alias =  ereg_replace(string: str,
		pattern: string("^[a-zA-Z0-9_-]+[ \t]+[0-9]+[ \t]*(.*)[\r\n]+"),
		replace: "\1");
    #if (! name) name="";
    #if (! alias) alias = "";

    #display("program=", program, "\nname=", name, "\nalias=", alias, "version=", version,"\nproto=", proto, "\nport=", port, "\nvalue follow=", vf,"\n\n");

    m = string("RPC program #", program, " version ", version);
    if (name) m = string(m, " '", name, "'");
    if (alias) m = string(m, " (", alias, ")");
    m = string(m, " on port ", port);
    if (proto == 6)
    {
      report_tcp[port] += m + '/TCP\n\n';
      #log_message(port: port, data: m);
      # Remember service
      if ( port <= 65535 && port > 0 )
      {
       if (name) register_service(port: port, proto: string("RPC/", name));
       else      register_service(port: port, proto: string("RPC/", program));
      }
    }
    if (proto == 17) report_udp[port] += m + '/UDP\n\n';
    i=i+1;
  }
}

# Report found ports for the port of the portmapper. Reporting them for their
# actual port would suggest that this port was actually scanned and checked, not
# just reported by the portmapper.

result = "These are the registered RPC programs:\n\n";

foreach port (keys(report_tcp))
{
  if (port > 0 && port <= 65535) result += report_tcp[port];
}

foreach port (keys(report_udp))
{
  if (port > 0 && port <= 65535) result += report_udp[port];
}

log_message(port:portmap, data:result);