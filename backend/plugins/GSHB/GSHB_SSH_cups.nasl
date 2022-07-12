###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_cups.nasl 10617 2018-07-25 13:47:49Z cfischer $
#
# Read /etc/cups/cupsd.conf and /etc/cups/client.conf
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
  script_oid("1.3.6.1.4.1.25623.1.0.96083");
  script_version("$Revision: 10617 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 15:47:49 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Read /etc/cups/cupsd.conf and /etc/cups/client.conf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_tag(name:"summary", value:"Read /etc/cups/cupsd.conf and /etc/cups/client.conf over an SSH Connection.");

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
    set_kb_item(name: "GSHB/cupsd", value:"error");
    set_kb_item(name: "GSHB/cupsclient", value:"error");
    set_kb_item(name: "GSHB/cupsd/log", value:error);
    exit(0);
}


SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item("ssh/login/uname");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");

  if (rpms){
    pkg1 = "cups";
    pkg2 = "cups-client";
    pkg3 = "cupsys";
    pkg4 = "cupsys-client";

    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    pat2 = string("ii  (", pkg2, ") +([0-9]:)?([^ ]+)");
    pat3 = string("ii  (", pkg3, ") +([0-9]:)?([^ ]+)");
    pat4 = string("ii  (", pkg4, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    desc3 = eregmatch(pattern:pat3, string:rpms);
    desc4 = eregmatch(pattern:pat4, string:rpms);
  }else{

    rpms = get_kb_item("ssh/login/rpms");

    tmp = split(rpms, keep:0);

    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');

    pkg1 = "cups";
    pkg2 = "cups-client";
    pkg3 = "cupsys";
    pkg4 = "cupsys-client";

    pat1 = string("(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat2 = string("(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat3 = string("(", pkg3, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    pat4 = string("(", pkg4, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    desc2 = eregmatch(pattern:pat2, string:rpms);
    desc3 = eregmatch(pattern:pat3, string:rpms);
    desc4 = eregmatch(pattern:pat4, string:rpms);
  }


  if (desc1 || desc3) cupsd = ssh_cmd(socket:sock, cmd:"cat /etc/cups/cupsd.conf");
  else cupsd = "nocupsd";
  if ("cat: /etc/cups/cupsd.conf:" >< cupsd) cupsd = "no cupsd.conf";
  else if (cupsd == "") cupsd = "empty";

  if (desc2 || desc4) cupsclient = ssh_cmd(socket:sock, cmd:"cat /etc/cups/client.conf");
  else if (desc1[3] =~ "[0-9]+.fc[0-9]+") cupsclient = ssh_cmd(socket:sock, cmd:"cat /etc/cups/client.conf");
  else cupsclient = "nocupsclient";
  if ("cat: /etc/cups/client.conf:" >< cupsclient) cupsclient = "no client.conf";
  else if (cupsclient == "") cupsclient = "empty";
}
else{
  cupsd = "windows";
  cupsclient = "windows";
}

set_kb_item(name: "GSHB/cupsd", value:cupsd);
set_kb_item(name: "GSHB/cupsclient", value:cupsclient);

exit(0);
