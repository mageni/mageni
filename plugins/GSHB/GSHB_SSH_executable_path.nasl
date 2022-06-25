###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_executable_path.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# List executable and writable-executable Files, list path variable
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
  script_oid("1.3.6.1.4.1.25623.1.0.96084");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("List executable and writable-executable Files, list path variable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"List executable and writable-executable Files, list path variable over an SSH Connection.

  Check for executable Files outside /usr/local/bin:/usr/bin:/bin:/usr/bin/X11:
  /usr/games:/sbin:/usr/sbin:/usr/local/sbin:, check for user write permission on
  valid executables.");

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
    set_kb_item(name: "GSHB/executable", value:"error");
    set_kb_item(name: "GSHB/write-executable", value:"error");
    set_kb_item(name: "GSHB/path", value:"error");
    set_kb_item(name: "GSHB/executable/log", value:error);
    exit(0);
}

executable = ssh_cmd(socket:sock, cmd:"find / -mount -type f -perm -001");
writeexecutable = ssh_cmd(socket:sock, cmd:"find / -mount -type f -perm -003");
path = ssh_cmd(socket:sock, cmd:"export");

#if ("FIND: Invalid switch" >< executable|| "FIND: Parameterformat falsch" >< executable){
#  set_kb_item(name: "GSHB/executable", value:"windows");
#  set_kb_item(name: "GSHB/write-executable", value:"windows");
#  set_kb_item(name: "GSHB/path", value:"windows");
#  exit(0);
#}

if (!executable) executable = "none";
else{
  Lst = split(executable, keep:0);
  executable = "";
  for (i=0; i<max_index(Lst); i++){
  if (Lst[i] =~ "^/usr/local/bin/.*" || Lst[i] =~ "^/usr/bin/.*" || Lst[i] =~ "^/bin/.*" || Lst[i] =~ "^/usr/games/.*" || Lst[i] =~ "^/sbin/.*" || Lst[i] =~ "^/usr/sbin/.*" ||  Lst[i] =~ "^/usr/local/sbin/.*" ||  Lst[i] =~ "^/var/lib/.*" ||  Lst[i] =~ "^/lib/.*" ||  Lst[i] =~ "^/usr/lib/.*" ||  Lst[i] =~ "^/etc/.*" ||  Lst[i] =~ ".*Keine Berechtigung.*" ||  Lst[i] =~ ".*Permission denied.*") continue;
  executable += Lst[i] + '\n';
  }
}

if (!writeexecutable) writeexecutable = "none";
else{
  Lst = split(writeexecutable, keep:0);
  if (Lst){
    writeexecutable = "";
    for (i=0; i<max_index(Lst); i++){
    if (Lst[i] =~ ".*Keine Berechtigung.*" ||  Lst[i] =~ ".*Permission denied.*") continue;
    writeexecutable += Lst[i] + '\n';
    }
  }
}
if (writeexecutable == "") writeexecutable = "none";

if (!path) path = "none";
else path = egrep(string:path, pattern:" PATH=", icase:0);


set_kb_item(name: "GSHB/executable", value:executable);
set_kb_item(name: "GSHB/write-executable", value:writeexecutable);
set_kb_item(name: "GSHB/path", value:path);
exit(0);
