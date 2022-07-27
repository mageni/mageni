###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_postgresql_no_password.nasl 10312 2018-06-25 11:10:27Z cfischer $
#
# PostgreSQL no password
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103798");
  script_version("$Revision: 10312 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 13:10:27 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2013-10-07 14:28:02 +0200 (Mon, 07 Oct 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("PostgreSQL no password");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_mandatory_keys("PostgreSQL/installed");

  script_tag(name:"solution", value:"Set a password as soon as possible.");

  script_tag(name:"summary", value:"It was possible to login into the remote PostgreSQL as user postgres without using a password.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");

port = get_app_port(cpe:CPE);
if(!port)port = 5432;
if(!get_tcp_port_state(port))exit(0);

function check_login(user, port) {

  local_var soc, req, len, data, res, typ, code, x;

  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  h = raw_string((0x03 >> 8) & 0xFF, 0x03 & 0xFF,(0x00 >> 8) & 0xFF, 0x00 & 0xFF);
  null = raw_string(0);

  req = string(h,
               "user",null,user,
               null,
               "database",null,"postgres",
               null,
               "client_encoding",null,"UNICODE",
               null,
               "DateStyle",null,"ISO",
               null,null);

  len = strlen(req) + 4;
  req = raw_string((len >> 24 ) & 0xff,(len >> 16 ) & 0xff, (len >>  8 ) & 0xff,(len) & 0xff) + req;

  send(socket:soc, data:req);
  res = recv(socket:soc, length:1);
  if (isnull(res) || res[0] != "R") {
    close(soc);
    exit(0);
  }

  res += recv(socket:soc, length:4);
  if (strlen(res) < 5) {
    close(soc);
    exit(0);
  }

  x = substr(res, 1, 4);

  len = ord(x[0]) << 24 | ord(x[1]) << 16 | ord(x[2]) << 8 | ord(x[3]);
  res += recv(socket:soc, length:len);

  if(strlen(res) < len || strlen(res) < 8) {
    close(soc);
    return FALSE;
  }

  typ = substr(res, strlen(res)-6,strlen(res)-5);
  typ = ord(typ[1]);

  if(typ != 0) {
    close(soc);
    return FALSE;
  }

  recv(socket:soc, length:65535);

  sql = "select version();";
  sqllen = strlen(sql) + 5;
  slen = raw_string((sqllen >> 24 ) & 0xff,(sqllen >> 16 ) & 0xff, (sqllen >>  8 ) & 0xff,(sqllen) & 0xff);

  req = raw_string(0x51) + slen + sql + raw_string(0x00);
  send(socket:soc, data:req);

  res = recv(socket:soc, length:1);

  if(isnull(res) || res[0] != "T") {
    close(soc);
    return FALSE;
  }

  res += recv(socket:soc, length:1024);

  close(soc);

  if("PostgreSQL" >< res && "SELECT" >< res) return TRUE;
  return FALSE;
}

if(check_login(port:port, user:"postgres")) {
  security_message(port:port);
  exit(0);
}

exit(99);
