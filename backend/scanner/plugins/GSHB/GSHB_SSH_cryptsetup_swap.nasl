###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_cryptsetup_swap.nasl 10617 2018-07-25 13:47:49Z cfischer $
#
# Test System if cryptsetup is installed and the SWAP Partition encrypted
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
  script_oid("1.3.6.1.4.1.25623.1.0.96087");
  script_version("$Revision: 10617 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 15:47:49 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-06-21 10:39:50 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Test System if cryptsetup is installed and the SWAP Partition encrypted");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_tag(name:"summary", value:"Test System if cryptsetup is installed and the SWAP Partition is encrypted.");

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

    set_kb_item(name: "GSHB/cryptsetup/inst", value:"error");
#    set_kb_item(name: "GSHB/cryptsetup/cryptdisks", value:"error");
#    set_kb_item(name: "GSHB/cryptsetup/crypttab", value:"error");
    set_kb_item(name: "GSHB/cryptsetup/fstab", value:"error");
    set_kb_item(name: "GSHB/cryptsetup/log", value:error);
    exit(0);
}
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item("ssh/login/uname");

if (SAMBA || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");

  if (rpms){
    pkg1 = "cryptsetup";
    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);

  }else{

    rpms = get_kb_item("ssh/login/rpms");
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');
    pkg1 = "cryptsetup";
    pat1 = string("(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
  }


  if (desc1) cryptsetupinst = "yes";
  else cryptsetupinst = "no";

  if (desc1){
    cryptdisks = ssh_cmd(socket:sock, cmd:"cat /etc/default/cryptdisks");
    crypttab = ssh_cmd(socket:sock, cmd:"cat /etc/crypttab");
    fstab = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/fstab");

    if (cryptdisks =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  cryptdisks =~ ".*No such file or directory.*") cryptdisks = "none";
    if (crypttab =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  crypttab =~ ".*No such file or directory.*") crypttab = "none";
    if (fstab =~ ".*Datei oder Verzeichnis nicht gefunden.*" ||  fstab =~ ".*No such file or directory.*") cryptdisks = "none";

    if (cryptdisks != "none"){
      val1 = egrep(string:cryptdisks, pattern:"CRYPTDISKS_ENABLE=Yes", icase:0);
      if (val1) cryptdisks = "yes";
      else cryptdisks = "no";
    }
    if (cryptdisks != "none" && cryptdisks == "yes" && crypttab != "none"){
      val2 = egrep(string:crypttab, pattern:"swap", icase:0);
      if (val2){
        tmp = ereg_replace(string:val2, pattern:" ", replace:"", icase:0);
        tmp = ereg_replace(string:tmp, pattern:'\t', replace:"", icase:0);
        tmp = split(tmp, sep:"/", keep:0);
        crypttab = tmp[0];
      }
      else crypttab = "no";
    }
    else crypttab = "no";
    if (cryptdisks != "none" && cryptdisks == "yes" && crypttab != "none" && crypttab != "no" && fstab != "none"){
      Lst = split(fstab, keep:0);
      value =  ".*/dev/mapper/" + crypttab + ".*swap.*";
      for(i=0; i<max_index(Lst); i++){
         if (ereg(string:Lst[i], pattern:value, icase:0))val3 += Lst[i] +'\n';
      }
      if (val3) fstab = val3;
      else fstab = "no";
    }
    else fstab = "no";
  }
}
else{
  set_kb_item(name: "GSHB/cryptsetup/inst", value:"windows");
  set_kb_item(name: "GSHB/cryptsetup/cryptdisks", value:"windows");
  set_kb_item(name: "GSHB/cryptsetup/crypttab", value:"windows");
  set_kb_item(name: "GSHB/cryptsetup/fstab", value:"windows");
}

if (!cryptdisks)cryptdisks = "none";
if (!crypttab)crypttab = "none";
if (!fstab)fstab = "none";

set_kb_item(name: "GSHB/cryptsetup/inst", value:cryptsetupinst);
#set_kb_item(name: "GSHB/cryptsetup/cryptdisks", value:cryptdisks);
#set_kb_item(name: "GSHB/cryptsetup/crypttab", value:crypttab);
set_kb_item(name: "GSHB/cryptsetup/fstab", value:fstab);

exit(0);
