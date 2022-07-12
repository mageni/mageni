###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_NIS.nasl 10617 2018-07-25 13:47:49Z cfischer $
#
# Test System if NIS Server ore Client installed
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
  script_oid("1.3.6.1.4.1.25623.1.0.96102");
  script_version("$Revision: 10617 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 15:47:49 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-05-07 15:05:51 +0200 (Fri, 07 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Test System if NIS Server ore Client installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_tag(name:"summary", value:"Test System if NIS Server or Client are installed.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

cmdline = 0;
include("ssh_func.inc");
include("smb_nt.inc");

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
    set_kb_item(name: "GSHB/NIS/server", value:"error");
    set_kb_item(name: "GSHB/NIS/client", value:"error");
    set_kb_item(name: "GSHB/NIS/ypbind", value:"error");
    set_kb_item(name: "GSHB/NIS/ypserv", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusUserwopw", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusGenUserwopw", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusUserwpw", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusGenUserwpw", value:"error");
    set_kb_item(name: "GSHB/NIS/LocalUID0", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusGroupwopw", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusGenGroupwopw", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusGroupwpw", value:"error");
    set_kb_item(name: "GSHB/NIS/NisPlusGenGroupwpw", value:"error");
    set_kb_item(name: "GSHB/NIS/hostsdeny", value:"error");
    set_kb_item(name: "GSHB/NIS/hostsallow", value:"error");
    set_kb_item(name: "GSHB/NIS/securenets", value:"error");
    set_kb_item(name: "GSHB/NIS/log", value:error);
    exit(0);
}
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item("ssh/login/uname");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");

  if (rpms){
    pkg1 = "nis";
    pkg2 = "yp-tools";
    pkg3 = "ypbind";
    pkg4 = "ypserv";
    pkg5 = "rpcbind";
    pkg6 = "portmap";

    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    pat2 = string("ii  (", pkg2, ") +([0-9]:)?([^ ]+)");
    pat3 = string("ii  (", pkg3, ") +([0-9]:)?([^ ]+)");
    pat4 = string("ii  (", pkg4, ") +([0-9]:)?([^ ]+)");
    pat5 = string("ii  (", pkg5, ") +([0-9]:)?([^ ]+)");
    pat6 = string("ii  (", pkg6, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    desc3 = eregmatch(pattern:pat3, string:rpms);
    desc4 = eregmatch(pattern:pat4, string:rpms);
    desc5 = eregmatch(pattern:pat5, string:rpms);
    desc6 = eregmatch(pattern:pat6, string:rpms);
  }else{

    rpms = get_kb_item("ssh/login/rpms");

    tmp = split(rpms, keep:0);

    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');

    pkg1 = "nis";
    pkg2 = "yp-tools";
    pkg3 = "ypbind";
    pkg4 = "ypserv";
    pkg5 = "rpcbind";
    pkg6 = "portmap";

    pat1 = string("(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    pat2 = string("(", pkg2, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    pat3 = string("(", pkg3, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    pat4 = string("(", pkg4, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    pat5 = string("(", pkg5, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    pat6 = string("(", pkg6, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    desc3 = eregmatch(pattern:pat3, string:rpms);
    desc4 = eregmatch(pattern:pat4, string:rpms);
    desc5 = eregmatch(pattern:pat5, string:rpms);
    desc6 = eregmatch(pattern:pat6, string:rpms);
  }


  if (desc1 || desc4) nisserver = "yes";
  else nisserver = "no";
  if ((desc1 && (desc5 || desc6)) || (desc2 && desc3 && (desc5 || desc6))) nisclient = "yes";
  else nisclient = "no";

  passwd = ssh_cmd(socket:sock, cmd:"cat /etc/passwd");
  group = ssh_cmd(socket:sock, cmd:"cat /etc/group");

  ypbind = ssh_cmd(socket:sock, cmd:"ps -C ypbind");
  if ("bash: /bin/ps:" >!< ypbind){
    Lst = split(ypbind, keep:0);
    if ("ypbind" >< Lst[1]) ypbind = "yes";
    else ypbind = "no";
  }else{
    ypbind = ssh_cmd(socket:sock, cmd:"rpcinfo -u localhost ypbind");
    if ("is not available" >< ypbind || "ist nicht verfügbar" >< ypbind) ypbind = "no";
    if ("ready and waiting" >< ypbind || "ist bereit und wartet" >< ypbind) ypbind = "yes";
    else ypbind = "unknown";
  }

  ypserv = ssh_cmd(socket:sock, cmd:"ps -C ypserv");
  if ("bash: /bin/ps:" >!< ypserv){
    Lst = split(ypserv, keep:0);
    if ("ypserv" >< Lst[1]) ypserv = "yes";
    else ypserv = "no";
  }else{
    ypserv = ssh_cmd(socket:sock, cmd:"rpcinfo -u localhost ypserv");
    if ("is not available" >< ypserv || "ist nicht verfügbar" >< ypserv) ypserv = "no";
    if ("ready and waiting" >< ypserv || "ist bereit und wartet" >< ypserv) ypserv = "yes";
    else ypserv = "unknown";
  }
}
else{
  nisserver = "windows";
  nisclient = "windows";
}


Lst = split(passwd, keep:0);
for(i=0; i<max_index(Lst); i++){
  if ("+::0:0:::" >< Lst[i]) NisPlusUserwopw = "yes";
  if ("+::::::" >< Lst[i]) NisPlusGenUserwopw = "yes";
  if ("+:*:0:0:::" >< Lst[i]) NisPlusUserwpw = "yes";
  if ("+:*:::::" >< Lst[i]) NisPlusGenUserwpw = "yes";
  if (Lst[i] =~ "^\+.*:.*:0:0:.*:.*:.*") userval = "yes";
  else  if (Lst[i] =~ "^\+.*::0:0:.*:.*:.*") userval = "yes";
  if (Lst[i] =~ "^[^\+]*:.*:0:0:.*:.*:.*") {
    if (userval != "yes") LocalUID0 = "first";
    else LocalUID0 = "not first";
  }
}
Lst = split(group, keep:0);
for(i=0; i<max_index(Lst); i++){
  if ("+::0:" >< Lst[i]) NisPlusGroupwopw = "yes";
  if ("+:::" >< Lst[i]) NisPlusGenGroupwopw = "yes";
  if ("+:*:0:" >< Lst[i]) NisPlusGroupwpw = "yes";
  if ("+:*::" >< Lst[i]) NisPlusGenGroupwpw = "yes";
}

  securenets = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/ypserv.securenets");
  hostsdeny = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/hosts.deny | grep ypserv:");
  hostsallow = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/hosts.allow | grep ypserv:");

  if (!hostsdeny || hostsdeny == "")hostsdeny = "noentry";
  if (!hostsallow || hostsallow == "")hostsallow = "noentry";
  if ("0.0.0.0" >< securenets){
    Lst = split(securenets, keep:0);
    for(i=0; i<max_index(Lst); i++){
      if (Lst[i] =~ "(#).*(0\.0\.0\.0.*0\.0\.0\.0)")continue;
      if (Lst[i] =~ ".*(0\.0\.0\.0.*0\.0\.0\.0)") securenetsval = "everybody";
    }
  }


if (!NisPlusUserwopw) NisPlusUserwopw = "no";
if (!NisPlusGenUserwopw) NisPlusGenUserwopw = "no";
if (!NisPlusUserwpw) NisPlusUserwpw = "no";
if (!NisPlusGenUserwpw) NisPlusGenUserwpw = "no";
if (!NisPlusUserwpw) NisPlusUserwpw = "no";
if (!NisPlusGroupwopw) NisPlusGroupwopw = "no";
if (!NisPlusGenGroupwopw) NisPlusGenGroupwopw = "no";
if (!NisPlusGroupwpw) NisPlusGroupwpw = "no";
if (!NisPlusGenGroupwpw) NisPlusGenGroupwpw = "no";
if (!LocalUID0) LocalUID0 = "no";
if (!securenetsval) securenetsval = "none";

set_kb_item(name: "GSHB/NIS/server", value:nisserver);
set_kb_item(name: "GSHB/NIS/client", value:nisclient);
set_kb_item(name: "GSHB/NIS/ypbind", value:ypbind);
set_kb_item(name: "GSHB/NIS/ypserv", value:ypserv);
set_kb_item(name: "GSHB/NIS/NisPlusUserwopw", value:NisPlusUserwopw);
set_kb_item(name: "GSHB/NIS/NisPlusGenUserwopw", value:NisPlusGenUserwopw);
set_kb_item(name: "GSHB/NIS/NisPlusUserwpw", value:NisPlusUserwpw);
set_kb_item(name: "GSHB/NIS/NisPlusGenUserwpw", value:NisPlusGenUserwpw);
set_kb_item(name: "GSHB/NIS/LocalUID0", value:LocalUID0);
set_kb_item(name: "GSHB/NIS/NisPlusGroupwopw", value:NisPlusGroupwopw);
set_kb_item(name: "GSHB/NIS/NisPlusGenGroupwopw", value:NisPlusGenGroupwpw);
set_kb_item(name: "GSHB/NIS/NisPlusGroupwpw", value:NisPlusGroupwpw);
set_kb_item(name: "GSHB/NIS/NisPlusGenGroupwpw", value:NisPlusGenGroupwpw);
set_kb_item(name: "GSHB/NIS/hostsdeny", value:hostsdeny);
set_kb_item(name: "GSHB/NIS/hostsallow", value:hostsallow);
set_kb_item(name: "GSHB/NIS/securenets", value:securenetsval);
exit(0);
