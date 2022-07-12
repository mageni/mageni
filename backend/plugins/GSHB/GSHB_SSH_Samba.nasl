###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_Samba.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Read Samba [global] and [netlogon] Configuration
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
  script_oid("1.3.6.1.4.1.25623.1.0.96093");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-05-25 17:00:55 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Read Samba [global] and [netlogon] Configuration");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Read Samba [global] and [netlogon] Configuration.");

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
#    set_kb_item(name: "GSHB/SAMBA/conf", value:"error");
    set_kb_item(name: "GSHB/SAMBA/global", value:"error");
    set_kb_item(name: "GSHB/SAMBA/netlogon", value:"error");
    set_kb_item(name: "GSHB/SAMBA/smbpasswd", value:"error");
    set_kb_item(name: "GSHB/SAMBA/secretstdb", value:"error");
    set_kb_item(name: "GSHB/SAMBA/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
#    set_kb_item(name: "GSHB/SAMBA/conf", value:"windows");
    set_kb_item(name: "GSHB/SAMBA/global", value:"windows");
    set_kb_item(name: "GSHB/SAMBA/netlogon", value:"windows");
    set_kb_item(name: "GSHB/SAMBA/smbpasswd", value:"windows");
    set_kb_item(name: "GSHB/SAMBA/secretstdb", value:"windows");
  exit(0);
}

smbpasswd =  ssh_cmd(socket:sock, cmd:"ls -l /etc/smbpasswd");
secretstdb =  ssh_cmd(socket:sock, cmd:"ls -l /var/lib/samba/secrets.tdb");
smbconf = ssh_cmd(socket:sock, cmd:"egrep -v '^(#|;)' /etc/samba/smb.conf");
if (smbconf =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  smbconf =~ ".*No such file or directory.*") smbconf = "none";
if (smbpasswd =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  smbpasswd =~ ".*No such file or directory.*") smbpasswd = "none";
if (secretstdb =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  secretstdb =~ ".*No such file or directory.*") secretstdb = "none";

if (smbconf != "none"){
  Lst = split(smbconf, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "")continue;
    val += Lst[i] + '\n';
  }
  if (!val) smbconf = "novalentrys";
  else smbconf = val;
}

if (smbconf == "none") global = "none";
else if (smbconf != "none" && smbconf != "novalentrys"){
  val = eregmatch(string:smbconf, pattern:"global.*]", icase:0);
  Lst = split(val[0], keep:0);
  for(i=1; i<max_index(Lst); i++){
    if ("[" >< Lst[i])i = 999999;
    else global += Lst[i] + '\n';
  }
  if (!global) global = "novalentrys";
}

if (smbconf == "none") netlogon = "none";
else if (smbconf != "none" && smbconf != "novalentrys"){
  val = eregmatch(string:smbconf, pattern:"netlogon.*]", icase:0);
  Lst = split(val[0], keep:0);
  for(i=1; i<max_index(Lst); i++){
    if ("[" >< Lst[i])i = 999999;
    else netlogon += Lst[i] + '\n';
  }
  if (!netlogon) netlogon = "novalentrys";
}

#set_kb_item(name: "GSHB/SAMBA/conf", value:smbconf);
set_kb_item(name: "GSHB/SAMBA/global", value:global);
set_kb_item(name: "GSHB/SAMBA/netlogon", value:netlogon);
set_kb_item(name: "GSHB/SAMBA/smbpasswd", value:smbpasswd);
set_kb_item(name: "GSHB/SAMBA/secretstdb", value:secretstdb);


exit(0);
