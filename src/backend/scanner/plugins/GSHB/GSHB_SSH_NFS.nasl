###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_NFS.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Check security mechanisms for NFS
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96092");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-05-21 15:05:08 +0200 (Fri, 21 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Check security mechanisms for NFS");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Check security mechanisms for NFS.");

  exit(0);
}

cmdline = 0;
include("ssh_func.inc");

port = get_preference("auth_port_ssh");
if(!port) port = get_kb_item("Services/ssh");
if(!port) {
    port = 22;
}
sock = ssh_login_or_reuse_connection();
if(!sock) {
    error = get_ssh_error();
    if (!error) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name: "GSHB/NFS/exports", value:"error");
    set_kb_item(name: "GSHB/NFS/dfstab", value:"error");
    set_kb_item(name: "GSHB/NFS/passwd", value:"error");
    set_kb_item(name: "GSHB/NFS/fstab", value:"error");
    set_kb_item(name: "GSHB/NFS/vfstab", value:"error");
#    set_kb_item(name: "GSHB/NFS/keyserv", value:"error");
    set_kb_item(name: "GSHB/NFS/lsexports", value:"error");
    set_kb_item(name: "GSHB/NFS/lsdfstab", value:"error");
    set_kb_item(name: "GSHB/NFS/lspasswd", value:"error");
    set_kb_item(name: "GSHB/NFS/lsfstab", value:"error");
    set_kb_item(name: "GSHB/NFS/lsvfstab", value:"error");
    set_kb_item(name: "GSHB/NFS/nfsd", value:"error");
    set_kb_item(name: "GSHB/NFS/mountd", value:"error");
    set_kb_item(name: "GSHB/NFS/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/NFS/exports", value:"windows");
    set_kb_item(name: "GSHB/NFS/dfstab", value:"windows");
    set_kb_item(name: "GSHB/NFS/passwd", value:"windows");
    set_kb_item(name: "GSHB/NFS/fstab", value:"windows");
    set_kb_item(name: "GSHB/NFS/vfstab", value:"windows");
    set_kb_item(name: "GSHB/NFS/lsexports", value:"windows");
    set_kb_item(name: "GSHB/NFS/lsdfstab", value:"windows");
    set_kb_item(name: "GSHB/NFS/lspasswd", value:"windows");
    set_kb_item(name: "GSHB/NFS/lsfstab", value:"windows");
    set_kb_item(name: "GSHB/NFS/lsvfstab", value:"windows");
    set_kb_item(name: "GSHB/NFS/nfsd", value:"windows");
    set_kb_item(name: "GSHB/NFS/mountd", value:"windows");
  exit(0);
}

exports = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/exports");
dfstab = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/dfs/dfstab");
passwd = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/passwd");
fstab = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/fstab");
vfstab = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/vfstab");
#keyserv = ssh_cmd(socket:sock, cmd:"LANG=C ps -C keyserv");

set_kb_item(name: "GSHB/NFS/dfstab/test", value:dfstab);#TEST

nfsd = ssh_cmd(socket:sock, cmd:"rpcinfo -u localhost nfs");
if (nfsd =~ ".*such.file.*directory"){
  nfsd = ssh_cmd(socket:sock, cmd:"/usr/sbin/rpcinfo -u localhost nfs");
}

mountd = ssh_cmd(socket:sock, cmd:"rpcinfo -u localhost mountd");
if (mountd =~ ".*such.file.*directory"){
  mountd = ssh_cmd(socket:sock, cmd:"/usr/sbin/rpcinfo -u localhost mountd");
}

if (nfsd == "Absolute path to 'rpcinfo' is '/usr/sbin/rpcinfo', so running it may require superuser privileges (eg. root)."){
  nfsd = ssh_cmd(socket:sock, cmd:"ps ax | grep nfsd");
  if (nfsd =~ '.*nfsd.*') nfsd = "true";
  else nfsd = "false";
}
else{
  if (nfsd =~ 'program 100003 version . ready and waiting' || nfsd =~ 'Program 100003 Version . ist bereit und wartet') nfsd = "true";
  else nfsd = "false";
}

if (mountd == "Absolute path to 'rpcinfo' is '/usr/sbin/rpcinfo', so running it may require superuser privileges (eg. root)."){
  mountd = ssh_cmd(socket:sock, cmd:"ps ax | grep mountd");
  if (mountd =~ '.*mountd.*') mountd = "true";
  else mountd = "false";
}
else{
  if (mountd =~ 'program 100005 version . ready and waiting' || mountd =~ 'Program 100005 Version . ist bereit und wartet') mountd = "true";
  else mountd = "false";
}

if (exports =~ ".*such.file.*directory" || exports =~ ".*can't open /etc/exports") exports = "none";
if (dfstab =~ ".*such.file.*directory" || dfstab =~ ".*can't open /etc/dfs/dfstab") dfstab = "none";
if (passwd =~ ".*such.file.*directory" || passwd =~ ".*can't open /etc/passwd") passwd = "none";
if (fstab =~ ".*such.file.*directory" || fstab =~ ".*can't open /etc/fstab") fstab = "none";
if (vfstab =~ ".*such.file.*directory" || vfstab =~ ".*can't open /etc/vfstab") vfstab = "none";
#if (keyserv =~ ".*Permission denied.*") keyserv = "noperm";

if (exports != "none" )lsexports = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/exports");
else lsexports = "none";
if (dfstab != "none" )lsdfstab = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/dfs/dfstab");
else lsdfstab = "none";
if (passwd != "none" )lspasswd = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/passwd");
else lspasswd = "none";
if (fstab != "none" )lsfstab = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/fstab");
else lsfstab = "none";
if (vfstab != "none" )lsvfstab = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/vfstab");
else lsvfstab = "none";



if (exports != "none"){
  Lst = split(exports, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "")continue;
    if (Lst[i] =~ ".*no_root_squash.*" || Lst[i] =~ ".*anon=0.*")val1 += Lst[i] + '\n';
  }
  if (!val1) exports = "ok";
  else exports = val1;
}

if (dfstab != "none"){
  Lst = split(dfstab, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "")continue;
    if (Lst[i] !~ ".*access=*" || Lst[i] =~ ".*anon=0.*")val2 += Lst[i] + '\n';
  }
  if (!val2) dfstab = "ok";
  else dfstab = val2;
}

if (fstab != "none"){
  Lst = split(fstab, keep:0);
  for(i=0; i<max_index(Lst); i++){
#    if (Lst[i] == "" || Lst[i] !~ ".*nfs.*")continue;
    if (Lst[i] == "")continue;
    val3 += Lst[i] + '\n';
  }
  if (!val3) fstab = "none";
  else fstab = val3;
}

if (vfstab != "none"){
  Lst = split(vfstab, keep:0);
  for(i=0; i<max_index(Lst); i++){
#    if (Lst[i] == "" || Lst[i] !~ ".*nfs.*")continue;
    if (Lst[i] == "")continue;
    val4 += Lst[i] + '\n';
  }
  if (!val4) vfstab = "none";
  else vfstab = val4;
}

if (passwd != "none"){
  Lst = split(passwd, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] != "nobody:*:-2:-2:anonymous user::")continue;
    val5 += Lst[i] + '\n';
  }
  if (!val5) passwd = "no_nobody";
  else passwd = "nobody";
}

set_kb_item(name: "GSHB/NFS/exports", value:exports);
set_kb_item(name: "GSHB/NFS/dfstab", value:dfstab);
set_kb_item(name: "GSHB/NFS/passwd", value:passwd);
set_kb_item(name: "GSHB/NFS/fstab", value:fstab);
set_kb_item(name: "GSHB/NFS/vfstab", value:vfstab);
#set_kb_item(name: "GSHB/NFS/keyserv", value:keyserv);

set_kb_item(name: "GSHB/NFS/lsexports", value:lsexports);
set_kb_item(name: "GSHB/NFS/lsdfstab", value:lsdfstab);
set_kb_item(name: "GSHB/NFS/lspasswd", value:lspasswd);
set_kb_item(name: "GSHB/NFS/lsfstab", value:lsfstab);
set_kb_item(name: "GSHB/NFS/lsvfstab", value:lsvfstab);

set_kb_item(name: "GSHB/NFS/nfsd", value:nfsd);
set_kb_item(name: "GSHB/NFS/mountd", value:mountd);
exit(0);
