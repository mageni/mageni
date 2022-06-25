###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_SSH_dns.nasl 10612 2018-07-25 12:26:01Z cfischer $
#
# Check if DNS client is active and working
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
  script_oid("1.3.6.1.4.1.25623.1.0.96103");
  script_version("$Revision: 10612 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 14:26:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-06-07 13:23:53 +0200 (Mon, 07 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("Check if DNS client is active and working");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_mandatory_keys("Compliance/Launch/GSHB");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "gather-package-list.nasl");

  script_tag(name:"summary", value:"This plugin uses ssh to Check if DNS client is active and working.");

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
    set_kb_item(name: "GSHB/DNSTEST/VAL1", value:"error");
    set_kb_item(name: "GSHB/DNSTEST/VAL2", value:"error");
    set_kb_item(name: "GSHB/DNSTEST/VAL3", value:"error");
    set_kb_item(name: "GSHB/DNSTEST/VAL4", value:"error");
    set_kb_item(name: "GSHB/DNSTEST/VAL5", value:"error");
    set_kb_item(name: "GSHB/DNSTEST/log", value:error);
    exit(0);
}

VAL1 = ssh_cmd(socket:sock, cmd:"host www.greenbone.net");
VAL2 = ssh_cmd(socket:sock, cmd:"host www.bsi.de");
VAL3 = ssh_cmd(socket:sock, cmd:"host www.intevation.de");
VAL4 = ssh_cmd(socket:sock, cmd:"host www.heise.de");
VAL5 = ssh_cmd(socket:sock, cmd:"host www.debian.org");

if (VAL1 =~ "www.greenbone.net has address.*") VAL1 = "TRUE";
else VAL1 = "FALSE";
if (VAL2 =~ "www.bsi.de has address.*") VAL2 = "TRUE";
else VAL2 = "FALSE";
if (VAL3 =~ "www.intevation.de has address.*") VAL3 = "TRUE";
else VAL3 = "FALSE";
if (VAL4 =~ "www.heise.de has address.*") VAL4 = "TRUE";
else VAL4 = "FALSE";
if (VAL5 =~ "www.debian.org has address.*") VAL5 = "TRUE";
else VAL5 = "FALSE";

set_kb_item(name: "GSHB/DNSTEST/VAL1", value:VAL1);
set_kb_item(name: "GSHB/DNSTEST/VAL2", value:VAL2);
set_kb_item(name: "GSHB/DNSTEST/VAL3", value:VAL3);
set_kb_item(name: "GSHB/DNSTEST/VAL4", value:VAL4);
set_kb_item(name: "GSHB/DNSTEST/VAL5", value:VAL5);
exit(0);
