###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_prev_sensitive_data_loss.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Check accessrights of ps, finger, who, last and /var/log/?tmp*
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
  script_oid("1.3.6.1.4.1.25623.1.0.96080");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-13 14:21:58 +0200 (Tue, 13 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Check accessrights of ps, finger, who, last and /var/log/?tmp*");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Check accessrights of ps, finger, who, last and /var/log/?tmp*.

  Check if ps, finger, who and last is not user executable, check perm 660 for /var/log/?tmp*");

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
    set_kb_item(name: "GSHB/ps", value:"error");
    set_kb_item(name: "GSHB/finger", value:"error");
    set_kb_item(name: "GSHB/who", value:"error");
    set_kb_item(name: "GSHB/last", value:"error");
    set_kb_item(name: "GSHB/tmpfiles", value:"error");
    set_kb_item(name: "GSHB/ps/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/ps", value:"windows");
    set_kb_item(name: "GSHB/finger", value:"windows");
    set_kb_item(name: "GSHB/who", value:"windows");
    set_kb_item(name: "GSHB/last", value:"windows");
    set_kb_item(name: "GSHB/tmpfiles", value:"windows");
  exit(0);
}


ps = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /bin/ps");
finger = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/finger");
who = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/who");
last = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /usr/bin/last");
tmpfiles = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /var/log/?tmp*");

if (ps =~ ".*such.file.*directory") ps = "none";
else if (!ps) ps = "none";
else{
  Lst = split(ps, sep:" ", keep:0);
  ps = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (finger =~ ".*such.file.*directory") finger = "none";
else if (!finger) finger = "none";
else{
  Lst = split(finger, sep:" ", keep:0);
  finger = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (who =~ ".*such.file.*directory") who = "none";
else if (!who) who = "none";
else{
  Lst = split(who, sep:" ", keep:0);
  who = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (last =~ ".*such.file.*directory") last = "none";
else if (!last) last = "none";
else{
  Lst = split(last, sep:" ", keep:0);
  last = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (tmpfiles =~ ".*such.file.*directory") tmpfiles = "none";
else if (!tmpfiles) tmpfiles = "none";
else{
  Lst = split(tmpfiles, keep:0);
  tmpfiles = "";
  for (i=0; i<max_index(Lst); i++){
    tmpLst = split(Lst[i], sep:" ", keep:0);
    tmpfiles += tmpLst[0] + ":" + tmpLst[2] + ":"  + tmpLst[3] + ":" + tmpLst[max_index(tmpLst)-1] +'\n';
  }
}

set_kb_item(name: "GSHB/ps", value:ps);
set_kb_item(name: "GSHB/finger", value:finger);
set_kb_item(name: "GSHB/who", value:who);
set_kb_item(name: "GSHB/last", value:last);
set_kb_item(name: "GSHB/tmpfiles", value:tmpfiles);
exit(0);
