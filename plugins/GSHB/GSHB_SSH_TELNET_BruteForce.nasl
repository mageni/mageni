###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_TELNET_BruteForce.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# SSH and Telnet BruteForce attack
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
  script_oid("1.3.6.1.4.1.25623.1.0.96104");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-09-28 12:16:21 +0200 (Tue, 28 Sep 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("IT-Grundschutz: SSH and Telnet BruteForce attack");
  script_add_preference(name:"BruteForce Attacke with Default-Usern and -Passwords", type:"checkbox", value:"no");
  script_category(ACT_ATTACK);
  script_timeout(2400);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "ssh_authorization.nasl");

  script_tag(name:"summary", value:"SSH and Telnet BruteForce attack.");

  exit(0);
}

include("telnet_func.inc");
include("ssh_func.inc");
include("default_account.inc");
include("GSHB_BruteForce.inc");

ssh_port = get_kb_item("Services/ssh");
if (!ssh_port) ssh_port = 22;

telnet_port = get_kb_item("Services/telnet");
if (!telnet_port) telnet_port = 23;

start = script_get_preference("BruteForce Attacke with Default-Usern and -Passwords");
if (start == "no"){
set_kb_item(name: "GSHB/BRUTEFORCE/SSH", value:"deactivated");
set_kb_item(name: "GSHB/BRUTEFORCE/TELNET", value:"deactivated");
exit(0);
}


function check_ssh_account(login, password){
  if (ssh_port){
    soc = open_sock_tcp(ssh_port);
    if (soc){
      val = ssh_login(socket:soc, login:login, password:password);
      close(soc);
      if ( val == 0 ) {
        return "TRUE";
	  }
      else return 0;
    }
    else ssh_port = 0;
  }
}

function check_telnet_account(login, password, port){
  soc = open_sock_tcp(port);
  if (!soc)
 	{
	  telnet_port = 0;
	  return;
	}
  ret = telnet_negotiate(socket:soc, pattern:"(ogin:|asscode:|assword:)");
  if(strlen(ret)){
    if ( stridx(ret, "sername:") != -1 || stridx(ret, "ogin:") != -1  )  {
      send(socket:soc, data:string(login, "\r\n"));
      ret=recv_until(socket:soc, pattern:"(assword:|asscode:)");
    }
    if ( stridx(ret, "assword:") == -1 && stridx(ret, "asscode:") == -1  )  {
      close(soc);
      return(0);
    }
  send(socket:soc, data:string(password, "\r\n"));
  r = recv(socket:soc, length:4096);
  send(socket:soc, data:string("ping\r\n"));
  r = recv_until(socket:soc, pattern:"(assword:|asscode:|ogin:|% Bad password)");
  if (!r) return "TRUE";
  close(soc);
 }

}

for(i=0; i<max_index(BruteForcePWList); i++){
   Lst = split(BruteForcePWList[i], sep:'|', keep:0);
   sshbrute = check_ssh_account(login:Lst[0], password:Lst[1]);
   if (sshbrute == "TRUE"){
     i = 999999;
     ssh_result = "Username: " + Lst[0] + ", Password: " + Lst[1];
   }else ssh_result = "ok";
}
if (ssh_port == 0) ssh_result = "nossh";

for(i=0; i<max_index(BruteForcePWList); i++){
  Lst = split(BruteForcePWList[i], sep:'|', keep:0);
  if (Lst[0] == "")continue;
  telnetbrute = check_telnet_account(login:Lst[0], password:Lst[1], port:telnet_port);
  if (telnetbrute == "TRUE"){
     i = 999999;
     telnet_result = "Username: " + Lst[0] + ", Password: " + Lst[1];
   }else telnet_result = "ok";
}
if (telnet_port == 0) telnet_result = "notelnet";

set_kb_item(name: "GSHB/BRUTEFORCE/SSH", value:ssh_result);
set_kb_item(name: "GSHB/BRUTEFORCE/TELNET", value:telnet_result);
exit(0);

