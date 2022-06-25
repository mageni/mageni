###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_passwords.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Get User without Password and User which have an PW and days since last Password change
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
  script_oid("1.3.6.1.4.1.25623.1.0.96071");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-03-18 11:06:19 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Get User without Password and User which have an PW and days since last Password change");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to get User without Password and User which have an PW and

  days since last Password change. If the testuser have no access to /etc/shadow
  an KB entry will set.");

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
    set_kb_item(name: "GSHB/etc_shadow", value:"error");
    set_kb_item(name: "GSHB/NoPWUser", value:"error");
    set_kb_item(name: "GSHB/PWUser", value:"error");
    set_kb_item(name: "GSHB/PWChange", value:"error");
    set_kb_item(name: "GSHB/PASS_MAX_DAYS", value:"error");
    set_kb_item(name: "GSHB/PASS_MIN_DAYS", value:"error");
    set_kb_item(name: "GSHB/PASS_WARN_AGE", value:"error");
    set_kb_item(name: "GSHB/etc_shadow/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/etc_shadow", value:"windows");
    set_kb_item(name: "GSHB/NoPWUser", value:"windows");
    set_kb_item(name: "GSHB/PWUser", value:"windows");
    set_kb_item(name: "GSHB/PWChange", value:"windows");
    set_kb_item(name: "GSHB/PASS_MAX_DAYS", value:"windows");
    set_kb_item(name: "GSHB/PASS_MIN_DAYS", value:"windows");
    set_kb_item(name: "GSHB/PASS_WARN_AGE", value:"windows");
  exit(0);
}

logindefs = ssh_cmd(socket:sock, cmd:"grep -v '^#' /etc/login.defs");
if ("grep: /etc/login.defs:" >< logindefs) logindefs = "nologindefs";
if ("Permission denied" >< logindefs || "Keine Berechtigung" >< logindefs) logindefs = "nopermission";
if (!logindefs) logindefs = "nologindefs";

if (logindefs >!< "nologindefs" && logindefs >!< "nopermission"){
  logindefs = toupper(logindefs);
  Lst = split(logindefs);
  for(i=0; i<max_index(Lst); i++){
   if ("PASS_MAX_DAYS" >< Lst[i]) PASS_MAX_DAYS = Lst[i];
   if ("PASS_MIN_DAYS" >< Lst[i]) PASS_MIN_DAYS = Lst[i];
   if ("PASS_WARN_AGE" >< Lst[i]) PASS_WARN_AGE = Lst[i];
  }
  if (PASS_MAX_DAYS){
    PASS_MAX_DAYS = PASS_MAX_DAYS - "PASS_MAX_DAYS";
    PASS_MAX_DAYS = PASS_MAX_DAYS - " ";
    PASS_MAX_DAYS = PASS_MAX_DAYS - '\t';
    PASS_MAX_DAYS = PASS_MAX_DAYS - '\n';
  }else PASS_MAX_DAYS = "none";
  if (PASS_MIN_DAYS){
    PASS_MIN_DAYS = PASS_MIN_DAYS - "PASS_MIN_DAYS";
    PASS_MIN_DAYS = PASS_MIN_DAYS - " ";
    PASS_MIN_DAYS = PASS_MIN_DAYS - '\t';
    PASS_MIN_DAYS = PASS_MIN_DAYS - '\n';
  }else PASS_MIN_DAYS = "none";
  if (PASS_WARN_AGE){
    PASS_WARN_AGE = PASS_WARN_AGE - "PASS_WARN_AGE";
    PASS_WARN_AGE = PASS_WARN_AGE - " ";
    PASS_WARN_AGE = PASS_WARN_AGE - '\t';
    PASS_WARN_AGE = PASS_WARN_AGE - '\n';
  }else PASS_WARN_AGE = "none";
}else {
  PASS_MAX_DAYS = logindefs;
  PASS_MIN_DAYS = logindefs;
  PASS_WARN_AGE = logindefs;
}

uname = get_kb_item( "ssh/login/uname" );
uname = ereg_replace(pattern:'\n',replace:'', string:uname);

secondssince = ssh_cmd(socket:sock, cmd:"date +'%s'");
dayssince = secondssince / 86400;
dayssince = ereg_replace(string:dayssince, pattern:"(\.[0-9].*|,[0-9].*)" ,replace:"");

shadow = ssh_cmd(socket:sock, cmd:"cat /etc/shadow");
if ("cat: /etc/aliases:" >< shadow) shadow = "noshadow";
if ("Permission denied" >< shadow || "Keine Berechtigung" >< shadow) shadow = "nopermission";
if (!shadow) shadow = "noshadow";

#shadow = "nopermission";#TEST

if (shadow >!< "noshadow" && shadow >!< "nopermission"){
  Lst = split(shadow);
  for(i=0; i<max_index(Lst); i++){
    UserLst = split(Lst[i], sep:":", keep:0);
    if (UserLst[1] != "*" && UserLst[1] != "!" && UserLst[1] != "*LK*" && UserLst[1] != "NP" && UserLst[4] > 90)PWChange += UserLst[0] + ":" + UserLst[4] + '\n';
    if (UserLst[1] == "!" || UserLst[1] == "NP") NoPWUser += UserLst[0] + '\n';
    else if (UserLst[1] == "*" || UserLst[1] == "*LK*") continue;
    else{
      days = int(dayssince) - int(UserLst[2]);
      PWUser += UserLst[0] + ":" + days + ';';
    }
  }
}else {
  if(uname !~ "SunOS .*"){
    userlist = ssh_cmd(socket:sock, cmd:"passwd -Sa");
    Lst = split(userlist);
    for(i=0; i<max_index(Lst); i++){
      UserLst = split(Lst[i], sep:" ", keep:0);
      if (UserLst[1] != "L" && UserLst[1] != "NP" && UserLst[4] > 90)PWChange += UserLst[0] + ":" + UserLst[4] + '\n';
      if (UserLst[1] == "NP") NoPWUser += UserLst[0] + '\n';
      else if (UserLst[1] == "L") continue;
      else{
        userlistdate =  split(UserLst[2], sep:"/", keep:0);
        userlisttime = mktime(mday:userlistdate[1], mon:userlistdate[0] , year:userlistdate[2] );
        userlisttime = userlisttime / 86400;
        days = int(dayssince) - int(userlisttime);
        PWUser += UserLst[0] + ":" + days + ';';
      }
    }
  }
  if(uname =~ "SunOS .*"){
    userlist = ssh_cmd(socket:sock, cmd:"passwd -sa");
    if (userlist =~ ".*ermission denied.*") sunpasswd = "noperm";
    else{
      sunpasswd = "ok";
      Lst = split(userlist);
      for(i=0; i<max_index(Lst); i++){
        if (Lst[i] =~ "^.*[ ]{1,}PS[ ]{1,}"){
          PS_Lst = split(Lst[i], sep:" ", keep:0);
          val = ssh_cmd(socket:sock, cmd:"logins -x -l " + PS_Lst[0] + " | grep PS");
          date_val = split(val, sep:"PS", keep:0);
          date_val = date_val[1];
          month = date_val[1] + date_val[2];
          day = date_val[3] + date_val[4];
          year = date_val[5] + date_val[6];
          if (int(year) > 20 ) year = "19" + year;
          else year = "20" + year;
          userlisttime = mktime(mday:day, mon:month , year:year );
          userlisttime = userlisttime / 86400;
          days = int(dayssince) - int(userlisttime);
          PWUser += PS_Lst[0] + ":" + days + ';';
        }
        else if (Lst[i] =~ "^.*[ ]{1,}NP[ ]{1,}"){
          NP_Lst = split(Lst[i], sep:" ", keep:0);
          NoPWUser += NP_Lst[0] + '\n';
        }
      }
    }
  }
}

if (!PWUser) PWUser = "none";
if (!NoPWUser) NoPWUser = "none";
if (!PWChange) PWChange = "none";

if (shadow >< "noshadow" || shadow >< "nopermission") set_kb_item(name: "GSHB/etc_shadow", value:shadow);
set_kb_item(name: "GSHB/SunPasswd", value:sunpasswd);
set_kb_item(name: "GSHB/NoPWUser", value:NoPWUser);
set_kb_item(name: "GSHB/PWUser", value:PWUser);
set_kb_item(name: "GSHB/PWChange", value:PWChange);
set_kb_item(name: "GSHB/PASS_MAX_DAYS", value:PASS_MAX_DAYS);
set_kb_item(name: "GSHB/PASS_MIN_DAYS", value:PASS_MIN_DAYS);
set_kb_item(name: "GSHB/PASS_WARN_AGE", value:PASS_WARN_AGE);
exit(0);
