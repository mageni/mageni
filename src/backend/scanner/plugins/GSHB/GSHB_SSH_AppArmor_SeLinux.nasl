###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_AppArmor_SeLinux.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Check for App-Armor and SeLinux
#
# Authors:
# Emanuel Moss <emanuel.moss@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.109039");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-01-02 10:56:23 +0200 (Tue, 02 Jan 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Test existence of App-Armor, SeLinux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This script checks the existence of App-Armor
  and SeLinux on a Linux host.");

  exit(0);
}

include("ssh_func.inc");

port = get_preference("auth_port_ssh");
if( !port ) port = get_kb_item("Services/ssh");
if( !port ) {
    port = 22;
}

sock = ssh_login_or_reuse_connection();
if( !sock ) {
    error = get_ssh_error();
    if ( !error ) error = "No SSH Port or Connection!";
    log_message(port:port, data:error);
    set_kb_item(name:"GSHB/AppArmor_SeLinux", value:"error");
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if( "windows" >< tolower(windowstest) && "interpreter" >< windowstest ){
  set_kb_item(name:"GSHB/AppArmor_SeLinux", value:"windows");
  exit(0);
}

cmd = 'dpkg -s apparmor';
AppArmorB = ssh_cmd(socket:sock, cmd:cmd);
AppArmor_Basic = ereg(string:AppArmorB, pattern:'package: apparmor.+status: install ok installed', icase: TRUE, multiline:TRUE);
cmd = 'dpkg -s apparmor-utils';
AppArmorU = ssh_cmd(socket:sock, cmd:cmd);
AppArmor_Utils = ereg(string:AppArmorU, pattern:'package: apparmor-utils.+status: install ok installed', icase:TRUE, multiline:TRUE);

if( AppArmor_Basic == "1" ) {
  set_kb_item(name:"GSHB/AppArmor_Basic", value:"1");
}else{
  set_kb_item(name:"GSHB/AppArmor_Basic", value:"0");
}

if( AppArmor_Utils != '1' ){
  set_kb_item(name:"GSHB/AppArmor_Utils", value:"0");
}else{
  set_kb_item(name:"GSHB/AppArmor_Utils", value:"1");
  cmd = '/usr/sbin/aa-status';
  apparmor_status = ssh_cmd(socket:sock, cmd:cmd);
  if( "no such file or directory" >< tolower(apparmor_status) || ! apparmor_status ||
      "command not found" >< tolower(apparmor_status) ){
    set_kb_item(name:"GSHB/AppArmor_Status", value:"error");
  }else{
    set_kb_item(name:"GSHB/AppArmor_Status", value:apparmor_status);
  }
}

cmd = 'dpkg -s selinux-basics';
SELinuxB = ssh_cmd(socket:sock, cmd:cmd);
cmd = 'dpkg -s selinux-utils';
SELinuxU = ssh_cmd(socket:sock, cmd:cmd);
SELinux_Basics = ereg(string:SELinuxB, pattern:'package: selinux-basics.+status: install ok installed', icase:TRUE, multiline:TRUE);
SELinux_Utils = ereg(string:SELinuxU, pattern:'package: selinux-utils.+status: install ok installed', icase:TRUE, multiline:TRUE);
if( SELinux_Basics == '1' ){
  set_kb_item(name:"GSHB/SeLinux_Basics", value:"1");
}else{
  set_kb_item(name:"GSHB/SeLinux_Basics", value:"0");
}

if( SELinux_Utils != '1' ){
  set_kb_item(name:"GSHB/SeLinux_Utils", value:"0");
}else{
  set_kb_item(name:"GSHB/SeLinux_Utils", value:"1");
  cmd = '/usr/sbin/sestatus -b';
  sestatus = ssh_cmd(socket:sock, cmd:cmd);
  if( ! sestatus || "command not found" >< tolower(sestatus) ||
      "no such file or directory" >< tolower(sestatus) ){
    set_kb_item(name:"GSHB/SeLinux_Status", value:"error");
  }else{
    set_kb_item(name:"GSHB/SeLinux_Status", value:sestatus);
  }
}

exit(0);
