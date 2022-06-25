###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_lastlogin.nasl 10616 2018-07-25 13:37:26Z cfischer $
#
# List Users, who was since 84 days not logged in to the System.
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
  script_oid("1.3.6.1.4.1.25623.1.0.96074");
  script_version("$Revision: 10616 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 15:37:26 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("List Users, who was since 84 days not logged in to the System.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to List Users, who was since 84 days not logged in to the System.");

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
    set_kb_item(name: "GSHB/lastlogin", value:"error");
    set_kb_item(name: "GSHB/LockedUser", value:"error");
    set_kb_item(name: "GSHB/UserShell", value:"error");
    set_kb_item(name: "GSHB/lastlogin/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/lastlogin", value:"windows");
    set_kb_item(name: "GSHB/LockedUser", value:"windows");
    set_kb_item(name: "GSHB/UserShell", value:"windows");
  exit(0);
}

lastlogin = ssh_cmd(socket:sock, cmd:"lastlog -b 84");
if ("grep: " >< lastlogin) lastlogin="none";
if (!lastlogin) lastlogin = "none";
#if (lastlogin >!< "none") lastlogin = ereg_replace(string:lastlogin, pattern:" {2,}", replace:":");

set_kb_item(name: "GSHB/lastlogin", value:lastlogin);

passwd = ssh_cmd(socket:sock, cmd:"cat /etc/passwd");
LockLst = split(passwd, keep:0);
for(i=0; i<max_index(LockLst); i++){
  LockUserLst = split(LockLst[i], sep:":", keep:0);
  if (LockUserLst[1] != "x" && LockUserLst[1] != "") LockUser += LockUserLst[0] + '\n';
}
if (!LockUser) LockUser = "none";
set_kb_item(name: "GSHB/LockedUser", value:LockUser);

lowpasswd = tolower(passwd);
ShellLst = split(lowpasswd, keep:0);
for(i=0; i<max_index(ShellLst); i++){
  ShellUserLst = split(ShellLst[i], sep:":", keep:0);
  if (ShellUserLst[6] != "/bin/false" && ShellUserLst[6] != "/usr/sbin/nologin" && ShellUserLst[6] != "/bin/sh") ShellUser += ShellUserLst[0] + ":" + ShellUserLst[6] + '\n';
}
if (!ShellUser) ShellUser = "none";
set_kb_item(name: "GSHB/UserShell", value:ShellUser);

exit(0);
