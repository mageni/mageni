###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_pubring.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Search and get size of pubring.gpg
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
  script_oid("1.3.6.1.4.1.25623.1.0.96070");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-27 10:02:59 +0200 (Tue, 27 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Search and get size of pubring.gpg");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Search and get size of pubring.gpg.");

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
    set_kb_item(name: "GSHB/pubrings", value:"error");
    set_kb_item(name: "GSHB/pubrings/log", value:error);
    exit(0);
}

pubringLst = ssh_cmd(socket:sock, cmd:"locate pubring.gpg");
if("command not found" >< pubringLst) pubringLst = ssh_cmd(socket:sock, cmd:"find /home /root -name pubring.gpg -type f -print");

if ("FIND: Invalid switch" >< pubringLst|| "FIND: Parameterformat falsch" >< pubringLst){
  set_kb_item(name: "GSHB/pubrings", value:"windows");
  exit(0);
}

if(pubringLst) {
  spList = split(pubringLst, keep:0);
  for(i=0; i<max_index(spList); i++){

    usrpubring = ssh_cmd(socket:sock, cmd:"ls -l " + spList[i]);
    usrpubring = split(usrpubring, keep:0);
    usrpubringzize = split(usrpubring[0], sep:" ", keep:0);
    usrname = split(usrpubringzize[7], sep:"/", keep:0);
    a = max_index(usrname) - 3;
    usrname = usrname[a];
    if (usrname == "") usrname = usrpubringzize[7];
    usrpubringzize = usrpubringzize[4];
    if (!usrname) usrname = usrpubringzize[7];
    if (usrpubringzize > 0) pubrings += usrname + '\n';
  }
}else pubrings = "none";

if (!pubrings) pubrings = "none";

set_kb_item(name: "GSHB/pubrings", value:pubrings);
exit(0);
