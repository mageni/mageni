###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_nsswitch.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Read /etc/nsswitch.conf and /etc/hosts.
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
  script_oid("1.3.6.1.4.1.25623.1.0.96076");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-04-09 13:42:26 +0200 (Fri, 09 Apr 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Read /etc/nsswitch.conf and /etc/hosts");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Read /etc/nsswitch.conf and /etc/hosts.");

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
    set_kb_item(name: "GSHB/nsswitch/passwd", value:"error");
    set_kb_item(name: "GSHB/nsswitch/group", value:"error");
    set_kb_item(name: "GSHB/nsswitch/hosts", value:"error");
    set_kb_item(name: "GSHB/dns/hosts", value:"error");
    set_kb_item(name: "GSHB/dns/log", value:error);
    exit(0);
}

windowstest = ssh_cmd(socket:sock, cmd:"cmd /?");
if (("windows" >< windowstest && "interpreter" >< windowstest) || ("Windows" >< windowstest && "interpreter" >< windowstest)){
    set_kb_item(name: "GSHB/nsswitch/passwd", value:"windows");
    set_kb_item(name: "GSHB/nsswitch/group", value:"windows");
    set_kb_item(name: "GSHB/nsswitch/hosts", value:"windows");
    set_kb_item(name: "GSHB/dns/hosts", value:"windows");
  exit(0);
}


nsswitch = ssh_cmd(socket:sock, cmd:"grep -v '^ *#' /etc/nsswitch.conf");
hosts = ssh_cmd(socket:sock, cmd:"grep -v '^ *#' /etc/hosts");

if ("grep: command not found" >< nsswitch) nsswitch = "nogrep";
if ("grep: command not found" >< hosts) hosts = "nogrep";
if ("grep: /etc/nsswitch:" >< nsswitch) nsswitch = "none";
if ("grep: /etc/hosts:" >< hosts) hosts = "none";

if (nsswitch != "nogrep" && nsswitch != "none"){
  passwd = egrep(string:nsswitch, pattern:"passwd:", icase:0);
  group = egrep(string:nsswitch, pattern:"group:", icase:0);
  nshosts = egrep(string:nsswitch, pattern:"hosts:", icase:0);
}


if (hosts != "nogrep" && hosts != "none"){
  Lst = split(hosts, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] == "") continue;
    hostsLst += Lst[i] + '\n';
  }
}

if (!nsswitch || nsswitch == " ") nsswitch = "none";
if (!hostsLst) hostsLst = "none";

set_kb_item(name: "GSHB/nsswitch/passwd", value:passwd);
set_kb_item(name: "GSHB/nsswitch/group", value:group);
set_kb_item(name: "GSHB/nsswitch/hosts", value:nshosts);
set_kb_item(name: "GSHB/dns/hosts", value:hostsLst);
exit(0);
