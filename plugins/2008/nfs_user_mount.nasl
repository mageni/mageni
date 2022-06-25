###############################################################################
# OpenVAS Vulnerability Test
# $Id: nfs_user_mount.nasl 12057 2018-10-24 12:23:19Z cfischer $
#
# User Mountable NFS shares
#
# Authors:
# Renaud Deraison, modified 2004 Michael Stone
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison, modified 2004 Michael Stone
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
  script_oid("1.3.6.1.4.1.25623.1.0.80028");
  script_version("$Revision: 12057 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 14:23:19 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("User Mountable NFS shares");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Renaud Deraison, modified 2004 Michael Stone");
  script_family("Remote file access");
  script_dependencies("secpod_rpc_portmap_tcp.nasl", "showmount.nasl");
  script_require_keys("rpc/portmap");

  script_tag(name:"summary", value:"It is possible to access the remote NFS shares without having root privileges.");

  script_tag(name:"insight", value:"Some of the NFS shares exported by the remote server could be
  mounted by the scanning host. An attacker may exploit this problem to gain read (and possibly write)
  access to files on remote host.

  Note that root privileges were not required to mount the remote shares. That is,
  the source port to mount the shares was bigger than 1024.");

  script_tag(name:"solution", value:"Configure NFS on the remote host so that only authorized hosts can mount
  the remote shares.

  The remote NFS server should prevent mount requests originating from a non-privileged port.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("nfs_func.inc");

mountable = NULL;

list = get_kb_list("nfs/exportlist");
if(isnull(list))exit(0);
shares = make_list(list);

port = get_rpc_port(program:100005, protocol:IPPROTO_UDP);
if ( ! port ) exit(0);
soc = open_sock_udp(port);

port2 = get_rpc_port(program:100003, protocol:IPPROTO_UDP);
if ( ! port2 ) exit(0);
soc2 = open_sock_udp(port2);

if(!soc)exit(0);

foreach share (shares){

  fid = mount(soc:soc, share:share);
  if(fid){

    content = readdir(soc:soc2, fid:fid);
    mountable += '+ ' + share + '\n' ;
    flag = 0;
    foreach c (content){
      if(flag == 0){
        mountable += ' + Contents of ' + share + ' : \n';
        flag = 1;
      }
      mountable += ' - ' + c + '\n';
    }
    umount(soc:soc, share:share);
    mountable += '\n\n';
  }
}

close(soc);

if(mountable) {
  report = string("The following NFS shares could be mounted without root privileges: \n", mountable);
  security_message(port:2049, proto:"udp", data:report);
}

exit(0);