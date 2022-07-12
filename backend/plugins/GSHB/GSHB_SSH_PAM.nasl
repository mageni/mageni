###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_PAM.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Check login, sshd, gdm, xdm and kde PAM Config
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
  script_oid("1.3.6.1.4.1.25623.1.0.96091");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-05-21 15:05:08 +0200 (Fri, 21 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Check login, sshd, gdm, xdm and kde PAM Config ");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Check login, sshd, gdm, xdm and kde PAM Config.

  This Script will check if pam_lastlog.so, pam_limits.so and pam_tally.so
  in /etc/pam.d/login, /etc/pam.d/sshd, /etc/pam.d/gdm, /etc/pam.d/xdm and
  /etc/pam.d/kde set.");

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
    set_kb_item(name: "GSHB/PAM/login", value:"error");
    set_kb_item(name: "GSHB/PAM/sshd", value:"error");
    set_kb_item(name: "GSHB/PAM/gdm", value:"error");
    set_kb_item(name: "GSHB/PAM/xdm", value:"error");
    set_kb_item(name: "GSHB/PAM/kde", value:"error");
    set_kb_item(name: "GSHB/PAM/limits", value:"error");
    set_kb_item(name: "GSHB/PAM/cracklib", value:"error");
    set_kb_item(name: "GSHB/PAM/unix", value:"error");
    set_kb_item(name: "GSHB/PAM/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/PAM/login", value:"windows");
    set_kb_item(name: "GSHB/PAM/sshd", value:"windows");
    set_kb_item(name: "GSHB/PAM/gdm", value:"windows");
    set_kb_item(name: "GSHB/PAM/xdm", value:"windows");
    set_kb_item(name: "GSHB/PAM/kde", value:"windows");
    set_kb_item(name: "GSHB/PAM/limits", value:"windows");
    set_kb_item(name: "GSHB/PAM/cracklib", value:"windows");
    set_kb_item(name: "GSHB/PAM/unix", value:"windows");
  exit(0);
}

uname = get_kb_item( "ssh/login/uname" );
uname = ereg_replace(pattern:'\n',replace:'', string:uname);

if (uname !~ "SunOS .*"){
  pamlogin = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/login");
  pamsshd = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/sshd");
  pamgdm = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/gdm");
  pamxdm = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/xdm");
  pamkde = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/kde");
  pamcomacc = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/common-account");
  pamcomses = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/common-session");
  pamcompas = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/common-password");
  pamcomauth = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/common-auth");
  limits = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/security/limits.conf");
  pampasswd = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/passwd");
  pamcompasswd = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.d/common-password");


  if (pamlogin =~ ".*such.file.*directory") pamlogin = "none";
  if (pamsshd =~ ".*such.file.*directory") pamsshd = "none";
  if (pamgdm =~ ".*such.file.*directory") pamgdm = "none";
  if (pamxdm =~ ".*such.file.*directory") pamxdm = "none";
  if (pamkde =~ ".*such.file.*directory") pamkde = "none";
  if (pamcomacc =~ ".*such.file.*directory") pamcomacc = "none";
  if (pamcomses =~ ".*such.file.*directory") pamcomses = "none";
  if (pamcompas =~ ".*such.file.*directory") pamcompas = "none";
  if (pamcomauth =~ ".*such.file.*directory") pamcomauth = "none";
  if (limits =~ ".*such.file.*directory") limits = "none";
  if (pampasswd =~ ".*such.file.*directory") pampasswd = "none";
  if (pamcompasswd =~ ".*such.file.*directory") pamcompasswd = "none";
}else if(uname =~ "SunOS .*"){
  set_kb_item(name: "GSHB/PAM/uname", value:uname);
  pamconf = ssh_cmd(socket:sock, cmd:"LANG=C grep -v '^#' /etc/pam.conf");
  if (pamconf =~ ".*such.file.*directory"){
    set_kb_item(name: "GSHB/PAM/CONF", value:"none");
  }
  else {
    set_kb_item(name: "GSHB/PAM/CONF", value:"read");
  }

}


if (limits == "") limits = "empty";

if (limits != "none" && limits != "empty"){
  Lst = split(limits, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "")continue;
    val += Lst[i] + '\n';
  }
  if (!val) limits = "novalentrys";
  else limits = val;
}

if (pamlogin != "none"){
  Lst = split(pamlogin, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    if (Lst[i] =~ '^.*session.*pam_lastlog.so.*showfailed.*')login_pamlastlog = "truefail";
    else if (Lst[i] =~ '^.*session.*pam_lastlog.so.*')login_pamlastlog = "true";
    if (Lst[i] =~ '^.*session.*required.*pam_limits.so.*')login_pamlimits = "true";
    if (Lst[i] =~ '^@include.*common-session,*'){
      Lst1 = split(pamcomses, keep:0);
      for(j=0; j<max_index(Lst1); j++){
        if (Lst1[j] == "") continue;
        if(login_pamlastlog != "truefail"){
          if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*showfailed.*')login_pamlastlog = "truefail";
          else if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*')login_pamlastlog = "true";
        }
        if(!login_pamlimits){
          if (Lst1[i] =~ '^.*session.*required.*pam_limits.so.*')login_pamlimits = "true";
        }
      }
    }
    if (Lst[i] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){login_pamtally = "true"; login_pamtally_data = Lst[i];}
    if (!login_pamtally){
      if (Lst[i] =~ '^@include.*common-auth,*'){
        Lst2 = split(pamcomauth, keep:0);
        for(k=0; k<max_index(Lst2); k++){
          if (Lst2[k] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){login_pamtally = "true"; login_pamtally_data = Lst2[k];}
        }
      }
    }
  }
  if (!login_pamlastlog)login_pamlastlog = "fail";
  if (!login_pamlimits)login_pamlimits = "fail";
  if (!login_pamtally)login_pamtally_data = "fail";
  if (!login_pamtally)login_pamtally = "fail";
  pamlogin = "read";
}
else{
  login_pamlastlog = "none";
  login_pamlimits = "none";
  login_pamtally = "none";
  login_pamtally_data = "none";
}

if (pamsshd != "none"){
  Lst = split(pamsshd, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    if (Lst[i] =~ '^.*session.*pam_lastlog.so.*showfailed.*')sshd_pamlastlog = "truefail";
    else if (Lst[i] =~ '^.*session.*pam_lastlog.so.*')sshd_pamlastlog = "true";
    if (Lst[i] =~ '^.*session.*required.*pam_limits.so.*')sshd_pamlimits = "true";
    if (Lst[i] =~ '^@include.*common-session,*'){
      Lst1 = split(pamcomses, keep:0);
      for(j=0; j<max_index(Lst1); j++){
        if (Lst1[j] == "") continue;
        if(sshd_pamlastlog != "truefail"){
          if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*showfailed.*')sshd_pamlastlog = "truefail";
          else if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*')sshd_pamlastlog = "true";
        }
        if(!sshd_pamlimits){
          if (Lst1[i] =~ '^.*session.*required.*pam_limits.so.*')sshd_pamlimits = "true";
        }
      }
    }
    if (Lst[i] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){sshd_pamtally = "true"; sshd_pamtally_data = Lst[i];}
    if (!sshd_pamtally){
      if (Lst[i] =~ '^@include.*common-auth,*'){
        Lst2 = split(pamcomauth, keep:0);
        for(k=0; k<max_index(Lst2); k++){
          if (Lst2[k] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){sshd_pamtally = "true"; sshd_pamtally_data = Lst2[k];}
        }
      }
    }
  }
  if (!sshd_pamlastlog)sshd_pamlastlog = "fail";
  if (!sshd_pamlimits)sshd_pamlimits = "fail";
  if (!sshd_pamtally)sshd_pamtally_data = "fail";
  if (!sshd_pamtally)sshd_pamtally = "fail";
  pamsshd = "read";
}
else{
  sshd_pamlastlog = "none";
  sshd_pamlimits = "none";
  sshd_pamtally = "none";
  sshd_pamtally_data = "none";
}

if (pamgdm != "none"){
  Lst = split(pamgdm, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    if (Lst[i] =~ '^.*session.*pam_lastlog.so.*showfailed.*')gdm_pamlastlog = "truefail";
    else if (Lst[i] =~ '^.*session.*pam_lastlog.so.*')gdm_pamlastlog = "true";
    if (Lst[i] =~ '^.*session.*required.*pam_limits.so.*')gdm_pamlimits = "true";
    if (Lst[i] =~ '^@include.*common-session,*'){
      Lst1 = split(pamcomses, keep:0);
      for(j=0; j<max_index(Lst1); j++){
        if (Lst1[j] == "") continue;
        if(gdm_pamlastlog != "truefail"){
          if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*showfailed.*')gdm_pamlastlog = "truefail";
          else if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*')gdm_pamlastlog = "true";
        }
        if(!gdm_pamlimits){
          if (Lst1[i] =~ '^.*session.*required.*pam_limits.so.*')gdm_pamlimits = "true";
        }
      }
    }
    if (Lst[i] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){gdm_pamtally = "true"; gdm_pamtally_data = Lst[i];}
    if (!gdm_pamtally){
      if (Lst[i] =~ '^@include.*common-auth,*'){
        Lst2 = split(pamcomauth, keep:0);
        for(k=0; k<max_index(Lst2); k++){
          if (Lst2[k] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){gdm_pamtally = "true"; gdm_pamtally_data = Lst2[k];}
        }
      }
    }
  }
  if (!gdm_pamlastlog)gdm_pamlastlog = "fail";
  if (!gdm_pamlimits)gdm_pamlimits = "fail";
  if (!gdm_pamtally)gdm_pamtally_data = "fail";
  if (!gdm_pamtally)gdm_pamtally = "fail";
  pamgdm = "read";
}
else{
  gdm_pamlastlog = "none";
  gdm_pamlimits = "none";
  gdm_pamtally = "none";
  gdm_pamtally_data = "none";
}

if (pamxdm != "none"){
  Lst = split(pamxdm, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    if (Lst[i] =~ '^.*session.*pam_lastlog.so.*showfailed.*')xdm_pamlastlog = "truefail";
    else if (Lst[i] =~ '^.*session.*pam_lastlog.so.*')xdm_pamlastlog = "true";
    if (Lst[i] =~ '^.*session.*required.*pam_limits.so.*')xdm_pamlimits = "true";
    if (Lst[i] =~ '^@include.*common-session,*'){
      Lst1 = split(pamcomses, keep:0);
      for(j=0; j<max_index(Lst1); j++){
        if (Lst1[j] == "") continue;
        if(xdm_pamlastlog != "truefail"){
          if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*showfailed.*')xdm_pamlastlog = "truefail";
          else if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*')xdm_pamlastlog = "true";
        }
        if(!xdm_pamlimits){
          if (Lst1[i] =~ '^.*session.*required.*pam_limits.so.*')xdm_pamlimits = "true";
        }
      }
    }
    if (Lst[i] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){xdm_pamtally = "true"; xdm_pamtally_data = Lst[i];}
    if (!xdm_pamtally){
      if (Lst[i] =~ '^@include.*common-auth,*'){
        Lst2 = split(pamcomauth, keep:0);
        for(k=0; k<max_index(Lst2); k++){
          if (Lst2[k] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){xdm_pamtally = "true"; xdm_pamtally_data = Lst2[k];}
        }
      }
    }
  }
  if (!xdm_pamlastlog)xdm_pamlastlog = "fail";
  if (!xdm_pamlimits)xdm_pamlimits = "fail";
  if (!xdm_pamtally)xdm_pamtally_data = "fail";
  if (!xdm_pamtally)xdm_pamtally = "fail";
  pamxdm = "read";
}
else{
  xdm_pamlastlog = "none";
  xdm_pamlimits = "none";
  xdm_pamtally = "none";
  xdm_pamtally_data = "none";
}

if (pamkde != "none"){
  Lst = split(pamkde, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    if (Lst[i] =~ '^.*session.*pam_lastlog.so.*showfailed.*')kde_pamlastlog = "truefail";
    else if (Lst[i] =~ '^.*session.*pam_lastlog.so.*')kde_pamlastlog = "true";
    if (Lst[i] =~ '^.*session.*required.*pam_limits.so.*')kde_pamlimits = "true";
    if (Lst[i] =~ '^@include.*common-session,*'){
      Lst1 = split(pamcomses, keep:0);
      for(j=0; j<max_index(Lst1); j++){
        if (Lst1[j] == "") continue;
        if(kde_pamlastlog != "truefail"){
          if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*showfailed.*')kde_pamlastlog = "truefail";
          else if (Lst1[j] =~ '^.*session.*pam_lastlog.so.*')kde_pamlastlog = "true";
        }
        if(!kde_pamlimits){
          if (Lst1[i] =~ '^.*session.*required.*pam_limits.so.*')kde_pamlimits = "true";
        }
      }
    }
    if (Lst[i] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){kde_pamtally = "true"; kde_pamtally_data = Lst[i];}
    if (!kde_pamtally){
      if (Lst[i] =~ '^@include.*common-auth,*'){
        Lst2 = split(pamcomauth, keep:0);
        for(k=0; k<max_index(Lst2); k++){
          if (Lst2[k] =~ '^.*auth.*required.*pam_tally.so.*deny=.*'){kde_pamtally = "true"; kde_pamtally_data = Lst2[k];}
        }
      }
    }
  }
  if (!kde_pamlastlog)kde_pamlastlog = "fail";
  if (!kde_pamlimits)kde_pamlimits = "fail";
  if (!kde_pamtally)kde_pamtally_data = "fail";
  if (!kde_pamtally)kde_pamtally = "fail";
  pamkde = "read";
}
else{
  kde_pamlastlog = "none";
  kde_pamlimits = "none";
  kde_pamtally = "none";
  kde_pamtally_data = "none";
}

if (pampasswd != "none"){
  Lst = split(pampasswd, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] =~ '^.*password.*required.*pam_cracklib.so.*')pam_cracklib += Lst[i] + '\n';
    if (Lst[i] =~ '^.*password.*required.*pam_unix.so.*')pam_unix += Lst[i] + '\n';
    if (Lst[i] =~ '^@include.*common-password.*'){
      Lst1 = split(pamcompasswd, keep:0);
      for(j=0; j<max_index(Lst1); j++){
        if (Lst1[j] =~ '^.*password.*required.*pam_cracklib.so.*')pam_cracklib += Lst1[j] + '\n';
        if (Lst1[j] =~ '^.*password.*required.*pam_unix.so.*')pam_unix += Lst1[j] + '\n';
      }
    }
  }
  if (!pam_cracklib) pam_cracklib = "none";
  if (!pam_unix) pam_unix = "none";
}else{
  pam_cracklib = pampasswd;
  pam_unix = pampasswd;
}


set_kb_item(name: "GSHB/PAM/login", value:pamlogin);
set_kb_item(name: "GSHB/PAM/login/lastlog", value:login_pamlastlog);
set_kb_item(name: "GSHB/PAM/login/limits", value:login_pamlimits);
set_kb_item(name: "GSHB/PAM/login/tally", value:login_pamtally);
set_kb_item(name: "GSHB/PAM/login/tally/data", value:login_pamtally_data);

set_kb_item(name: "GSHB/PAM/sshd", value:pamsshd);
set_kb_item(name: "GSHB/PAM/sshd/lastlog", value:sshd_pamlastlog);
set_kb_item(name: "GSHB/PAM/sshd/limits", value:sshd_pamlimits);
set_kb_item(name: "GSHB/PAM/sshd/tally", value:sshd_pamtally);
set_kb_item(name: "GSHB/PAM/sshd/tally/data", value:sshd_pamtally_data);

set_kb_item(name: "GSHB/PAM/gdm", value:pamgdm);
set_kb_item(name: "GSHB/PAM/gdm/lastlog", value:gdm_pamlastlog);
set_kb_item(name: "GSHB/PAM/gdm/limits", value:gdm_pamlimits);
set_kb_item(name: "GSHB/PAM/gdm/tally", value:gdm_pamtally);
set_kb_item(name: "GSHB/PAM/gdm/tally/data", value:gdm_pamtally_data);

set_kb_item(name: "GSHB/PAM/xdm", value:pamxdm);
set_kb_item(name: "GSHB/PAM/xdm/lastlog", value:xdm_pamlastlog);
set_kb_item(name: "GSHB/PAM/xdm/limits", value:xdm_pamlimits);
set_kb_item(name: "GSHB/PAM/xdm/tally", value:xdm_pamtally);
set_kb_item(name: "GSHB/PAM/xdm/tally/data", value:xdm_pamtally_data);

set_kb_item(name: "GSHB/PAM/kde", value:pamkde);
set_kb_item(name: "GSHB/PAM/kde/lastlog", value:kde_pamlastlog);
set_kb_item(name: "GSHB/PAM/kde/limits", value:kde_pamlimits);
set_kb_item(name: "GSHB/PAM/kde/tally", value:kde_pamtally);
set_kb_item(name: "GSHB/PAM/kde/tally/data", value:kde_pamtally_data);

set_kb_item(name: "GSHB/PAM/cracklib", value:pam_cracklib);
set_kb_item(name: "GSHB/PAM/unix", value:pam_unix);

set_kb_item(name: "GSHB/PAM/limits", value:limits);

exit(0);
