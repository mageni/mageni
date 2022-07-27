###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_SAMBA_ntfs_ACL_ADS.nasl 10617 2018-07-25 13:47:49Z cfischer $
#
# Check if NTFS Access Control Lists and NTFS Alternate Data Streams supported
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
  script_oid("1.3.6.1.4.1.25623.1.0.96090");
  script_version("$Revision: 10617 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 15:47:49 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-05-12 13:28:00 +0200 (Wed, 12 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Check if NTFS Access Control Lists and NTFS Alternate Data Streams supported");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB");

  script_tag(name:"summary", value:"Check if NTFS Access Control Lists and NTFS Alternate Data Streams supported.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

cmdline = 0;
include("ssh_func.inc");
include("version_func.inc");
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
    set_kb_item(name: "GSHB/SAMBA/NTFSADS", value:"error");
    set_kb_item(name: "GSHB/SAMBA/ACL", value:"error");
    set_kb_item(name: "GSHB/SAMBA/ACLSUPP", value:"error");
    set_kb_item(name: "GSHB/SAMBA/VER", value:"error");
    set_kb_item(name: "GSHB/SAMBA/log", value:error);
    exit(0);
}

samba = kb_smb_is_samba();

if (samba){

  rpms = get_kb_item("ssh/login/packages");

  if (rpms){
    pkg1 = "samba";
    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    ver = desc1[3];
  }else{

    rpms = get_kb_item("ssh/login/rpms");
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');
    pkg1 = "samba";
    pat1 = string("(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
    ver = desc1[2];
  }
  if(version_is_greater_equal(version:ver, test_version:"3.2.0")) NTFSADS = "yes";
  else NTFSADS = "no";
  fstab = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/fstab");
  if ("acl," >!< fstab && ",acl" >!< fstab) ACL = "no";
  else{
    Lst = split(fstab, keep:0);
    for(i=0; i<max_index(Lst); i++){
      if ("acl," >< Lst[i] || ",acl" >< Lst[i]) ACL += Lst[i] + '\n';
    }
  }
  smbconf = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/samba/smb.conf");
  smbconf = tolower(smbconf);
  if ("nt acl support = yes" >< smbconf) ACLSUPP = "yes";
  else ACLSUPP = "no";

  set_kb_item(name: "GSHB/SAMBA/NTFSADS", value:NTFSADS);
  set_kb_item(name: "GSHB/SAMBA/ACL", value:ACL);
  set_kb_item(name: "GSHB/SAMBA/ACLSUPP", value:ACLSUPP);
  set_kb_item(name: "GSHB/SAMBA/VER", value:ver);
}
else {
  set_kb_item(name: "GSHB/SAMBA/NTFSADS", value:"none");
  set_kb_item(name: "GSHB/SAMBA/ACL", value:"none");
  set_kb_item(name: "GSHB/SAMBA/ACLSUPP", value:"none");
  set_kb_item(name: "GSHB/SAMBA/VER", value:"none");
}
exit(0);
