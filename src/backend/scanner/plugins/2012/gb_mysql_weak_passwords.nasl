###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mysql_weak_passwords.nasl 12175 2018-10-31 06:20:00Z ckuersteiner $
#
# MySQL / MariaDB weak password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103551");
  script_version("$Revision: 12175 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-31 07:20:00 +0100 (Wed, 31 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-08-23 10:38:09 +0200 (Thu, 23 Aug 2012)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("MySQL / MariaDB weak password");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("mysql_version.nasl");
  script_require_ports("Services/mysql", 3306);
  script_mandatory_keys("MySQL_MariaDB/installed");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"summary", value:"It was possible to login into the remote MySQL as
  root using weak credentials.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

cpe_list = make_list( "cpe:/a:mysql:mysql",
                      "cpe:/a:oracle:mysql",
                      "cpe:/a:mariadb:mariadb" );

if( ! infos = get_all_app_ports_from_list( cpe_list:cpe_list ) ) exit( 0 );
port = infos['port'];
cpe  = infos['cpe'];

if( get_kb_item( "MySQL/" + port + "/blocked" ) ) exit( 0 );
if( ! get_app_location( cpe:cpe, port:port, nofork:TRUE ) ) exit( 0 ); # To have a reference to the Detection-NVT

username = "root";
passwords = make_list("admin", "root", "mysql", "password", "passw0rd", "123456", "12345678", "mysqladmin", "qwerty", "letmein", "database", "");

foreach password (passwords) {

  ver = "";
  pass = "";
  req = "";
  native = FALSE;

  sock = open_sock_tcp(port);
  if(!sock)exit(0);

  res = recv(socket:sock, length:4);
  if(!res) {
    close(sock);
    exit(0);
  }

  plen = ord(res[0]) + (ord(res[1])/8) + (ord(res[2])/16);
  res =  recv(socket:sock, length:plen);

  if("mysql_native_password" >< res)native = TRUE;

  for (i=0; i<strlen(res); i++)  {
    if (ord(res[i]) != 0) {
      ver += res[i];
    }
      else {
      break;
    }
  }

  p = strlen(ver);
  if(p < 5) {
    close(sock);
    exit(0);
  }

  caps = substr(res, 14+p, 15+p);
  if(!caps)continue;

  caps = ord(caps[0]) | ord(caps[1]) << 8;
  proto_is_41 = (caps & 512);
  if(!proto_is_41) {
    close(sock);
    exit(0);
  }

  salt = substr(res, 5+p, 12+p);

  if(strlen(res) > (44+p)) {
    salt += substr(res, 32+p, 43+p);
  }

  sha_pass1 = SHA1(password);
  sha_pass2 = SHA1(sha_pass1);
  sha_pass3 = SHA1(salt + sha_pass2);

  l = strlen(sha_pass3);

  for (i=0; i<l; i++) {
    pass += raw_string(ord(sha_pass1[i]) ^ ord(sha_pass3[i]));
  }

  req = raw_string(0x05,0xa6,0x0f,0x00,0x00,0x00,0x00,0x01,0x21,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00);

  req += raw_string(username,0x00);

  if(strlen(password) >0) {
    req += raw_string(0x14,pass);
  } else {
    req += raw_string(0x00);
  }

  if(native) req += raw_string(0x6d,0x79,0x73,0x71,0x6c,0x5f,0x6e,0x61,0x74,0x69,0x76,0x65,0x5f,0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,0x00);

  len = strlen(req);
  req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x01) + req;

  send(socket:sock,data:req);
  res =  recv(socket:sock, length:4);

  if(!res || strlen(res) < 4) {
    close(sock);
    continue;
  }

  plen = ord(res[0]) + (ord(res[1])/8) + (ord(res[2])/16);

  res =  recv(socket:sock, length:plen);
  if(!res || strlen(res) < plen) {
    close(sock);
    continue;
  }

  errno = ord(res[2]) << 8 | ord(res[1]);

  if(errno > 0 || errno == "") {
    close(sock);
    continue;
  }

  cmd = 'show databases';
  len = strlen(cmd) + 1;
  req = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff, 0x00, 0x03, cmd);

  send(socket:sock,data:req);

  z = 0;
  while(1) {

    z++;
    if(z > 15)exit(0);
    res =  recv(socket:sock, length:4);

    if(!res || strlen(res) < 4) {
      close(sock);
      exit(0);
    }

    plen = ord(res[0]) + (ord(res[1])/8) + (ord(res[2])/16);

    res =  recv(socket:sock, length:plen);
    if(!res || strlen(res) < plen)break;

    if("information_schema" >< res) {
      close(sock);

      data = 'It was possible to login as root';

      if(strlen(password) > 0) {
        data += ' with password "' + password + '".';
      } else {
        data += ' with an empty password.';
      }

      data += '\n\n';

      security_message(port:port,data:data);
      exit(0);
    }
  }
  close(sock);
}

close(sock);
exit(99);
