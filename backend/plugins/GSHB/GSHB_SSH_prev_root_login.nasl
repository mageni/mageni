###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_prev_root_login.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Read configs to prevent root login.
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
  script_oid("1.3.6.1.4.1.25623.1.0.96079");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Read configs to prevent root login ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Read configs to prevent root login:

  Check for /etc/securettys show all non console, check if root login is not
  possible via SSH, check for SYSLOG_SU_ENAB in /etc/login.defs,
  check for perm 0644 on /etc/securettys /etc/login.defs /etc/sshd/sshd_config,
  check if root_squash is enabled on all NFS mounts");

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
    set_kb_item(name: "GSHB/securetty", value:"error");
    set_kb_item(name: "GSHB/sshdconfig", value:"error");
    set_kb_item(name: "GSHB/logindefs", value:"error");
    set_kb_item(name: "GSHB/nfsexports", value:"error");
    set_kb_item(name: "GSHB/securetty/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/securetty", value:"windows");
    set_kb_item(name: "GSHB/sshdconfig", value:"windows");
    set_kb_item(name: "GSHB/logindefs", value:"windows");
    set_kb_item(name: "GSHB/nfsexports", value:"windows");
  exit(0);
}

uname =  get_kb_item( "ssh/login/uname" );
uname = ereg_replace(pattern:'\n',replace:'', string:uname);

securetty = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/securetty");
sshdconfig = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/ssh/sshd_config");
logindefs = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/login.defs");
nfsexports = ssh_cmd(socket:sock, cmd:"LANG=C cat /etc/exports");

lssecuretty = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/securetty");
lssshdconfig = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/ssh/sshd_config");
lslogindefs = ssh_cmd(socket:sock, cmd:"LANG=C ls -l /etc/login.defs");

if ("cat: command not found" >< securetty)securetty = "nocat";
else if ("cat: /etc/securetty: Permission denied" >< securetty) securetty = "noperm";
else if ("cat: cannot access /etc/securetty:" >< securetty) securetty = "none";
else if ("cat: cannot open /etc/securetty" >< securetty) securetty = "none";
else if ("cat: /etc/securetty:" >< securetty) securetty = "none";
else{
  Lst = split(securetty,keep:0);
  for (i=0; i<max_index(Lst); i++){
    result = eregmatch(string:Lst[i], pattern:'^ *#', icase:0);
    if (!result){
      if (Lst[i] !~ '^tty.*' && Lst[i] != '' && Lst[i] !~ "(C|c)(O|o)(N|n)(S|s)(O|o)(L|l)(E|e)"){
        if (Lst[i] !~ '^:[0-9]{1}.*') nonsecuretty += Lst[i] + '\n';
      }
    }
  }
if(nonsecuretty) securetty = nonsecuretty;
else securetty = "secure";
}

if ("cat: command not found" >< sshdconfig)sshdconfig = "nocat";
else if ("cat: /etc/ssh/sshd_config: Permission denied" >< sshdconfig) sshdconfig = "noperm";
else if ("cat: cannot access /etc/ssh/sshd_config:" >< sshdconfig) sshdconfig = "none";
else if ("cat: /etc/ssh/sshd_config:" >< sshdconfig) sshdconfig = "none";
else {
  rootlogin = egrep (string:sshdconfig, pattern:"PermitRootLogin", icase:0);
  Lst = split(rootlogin,keep:0);
  if (Lst){
    for (i=0; i<max_index(Lst); i++){
      result = eregmatch(string:Lst[i], pattern:'^ *#', icase:0);
      if (!result) login += Lst[i];
    }
  }else{
    result = eregmatch(string:rootlogin, pattern:'^ *#', icase:0);
    if (!result) login = rootlogin;
  }
  rootlogin = eregmatch(string:login, pattern:'yes', icase:0);
  if (!rootlogin) sshdconfig = "norootlogin";
  else sshdconfig = "rootlogin";
}

if ("cat: command not found" >< logindefs)logindefs = "nocat";
else if ("cat: /etc/login.defs: Permission denied" >< logindefs) logindefs = "noperm";
else if ("cat: cannot access /etc/login.defs:" >< logindefs) logindefs = "none";
else if ("cat: /etc/login.defs:" >< logindefs) logindefs = "none";
else {
  syslogsuenab = egrep(string:logindefs, pattern:"SYSLOG_SU_ENAB", icase:0);
  Lst = split(syslogsuenab,keep:0);
  if (Lst){
    for (i=0; i<max_index(Lst); i++){
      result = eregmatch(string:Lst[i], pattern:'^ *#', icase:0);
      if (!result) syslog += Lst[i] + '\n';
    }
  }else{
    result = eregmatch(string:syslogsuenab, pattern:'^ *#', icase:0);
    if (!result) syslog = syslogsuenab;
  }
  syslogenab = eregmatch(string:syslog, pattern:'yes', icase:0);
  if (!syslogenab) logindefs = "nosyslogsuenab";
  else logindefs = "syslogsuenab";
}

if (!nfsexports) nfsexports = "none";
else if ("cat: command not found" >< securetty)  nfsexports = "nocat";
#else if (nfsexports =~ '^\n') nfsexports = "none";
else if ("cat: /etc/exports: Permission denied" >< nfsexports) nfsexports = "noperm";
else if ("cat: cannot access /etc/exports:" >< nfsexports) nfsexports = "none";
else if ("cat: cannot open /etc/exports:" >< nfsexports) nfsexports = "none";
else if ("cat: /etc/exports:" >< nfsexports) nfsexports = "none";
else {

  org_nfsexports = nfsexports;
  Lst = split(nfsexports,keep:0);
  for (i=0; i<max_index(Lst); i++){
    result = eregmatch(string:Lst[i], pattern:'^ *#', icase:0);
    if (!result){
      result = eregmatch(string:Lst[i], pattern:' */.*', icase:0);
      if (result)val += result[0] +'\n';
    }
  }
  nfsexports = val;
  Lst = split(nfsexports,keep:0);
  if (Lst){
    for (i=0; i<max_index(Lst); i++){
      result = eregmatch(string:Lst[i], pattern:'no_root_squash', icase:0);
      if (!result){
        result = eregmatch(string:Lst[i], pattern:'root_squash', icase:0);
        if (result) rootsquash += Lst[i] + '\n';
        else if (Lst[i] !~ '^ *\n' && Lst[i] != "")norootsquash += Lst[i] + '\n';
      }else if (Lst[i] !~ '^ *\n' && Lst[i] != "")norootsquash += Lst[i] + '\n';
    }
  }else{
  result = eregmatch(string:nfsexports, pattern:'no_root_squash', icase:0);
  if (!result){
    result = eregmatch(string:nfsexports, pattern:'root_squash', icase:0);
    if (result) rootsquash = nfsexports;
    else norootsquash = nfsexports;
  } else norootsquash = nfsexports;
  }

if(norootsquash =~ '^ *\n') norootsquash = "none";
if(rootsquash =~ '^ *\n') rootsquash = "none";
if (!nfsexports && org_nfsexports) nfsexports = org_nfsexports;
}


if (lssecuretty =~ ".*No such file or directory.*") lssecuretty = "none";
else if (!lssecuretty) lssecuretty = "none";
else{
  Lst = split(lssecuretty, sep:" ", keep:0);
  lssecuretty = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (lssshdconfig =~ ".*No such file or directory.*") lssshdconfig = "none";
else if (!lssshdconfig) lssshdconfig = "none";
else{
  Lst = split(lssshdconfig, sep:" ", keep:0);
  lssshdconfig = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (lslogindefs =~ ".*No such file or directory.*") lslogindefs = "none";
else if (!lslogindefs) lslogindefs = "none";
else{
  Lst = split(lslogindefs, sep:" ", keep:0);
  lslogindefs = Lst[0] + ":" + Lst[2] + ":"  + Lst[3];
}

if (!norootsquash) norootsquash = "none";
if (!rootsquash) rootsquash = "none";

set_kb_item(name: "GSHB/securetty/nonconsole", value:securetty);
set_kb_item(name: "GSHB/sshdconfig/PermitRootLogin", value:sshdconfig);
set_kb_item(name: "GSHB/logindefs/syslogsuenab", value:logindefs);
set_kb_item(name: "GSHB/nfsexports", value:nfsexports);
set_kb_item(name: "GSHB/nfsexports/norootsquash", value:norootsquash);
set_kb_item(name: "GSHB/nfsexports/rootsquash", value:rootsquash);
set_kb_item(name: "GSHB/securetty/perm", value:lssecuretty);
set_kb_item(name: "GSHB/sshdconfig/perm", value:lssshdconfig);
set_kb_item(name: "GSHB/logindefs/perm", value:lslogindefs);
set_kb_item(name: "GSHB/uname", value:uname);
exit(0);
