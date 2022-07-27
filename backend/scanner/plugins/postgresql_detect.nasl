###############################################################################
# OpenVAS Vulnerability Test
# $Id: postgresql_detect.nasl 14324 2019-03-19 13:31:53Z cfischer $
#
# PostgreSQL Detection
#
# Authors:
# Michael Meyer  <michael.meyer@greenbone.net>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-03-30
# Modified the regex to detect alpha versions also.
#
# Updated by: <jan-oliver.wagner@greenbone.net> on 2011-11-21
# Revsied to comply with Change Request #57.
#
# Copyright:
# Copyright (c) 2009, 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100151");
  script_version("$Revision: 14324 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:31:53 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-23 21:21:19 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("PostgreSQL Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009, 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_add_preference(name:"Postgres Username:", value:"postgres", type:"entry");
  script_add_preference(name:"Postgres Password:", value:"postgres", type:"password");

  script_xref(name:"URL", value:"https://www.postgresql.org/");

  script_tag(name:"summary", value:"Detection of PostgreSQL, a open source object-relational
  database system.

  The script sends a connection request to the server (user:postgres, DB:postgres)
  and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

include("misc_func.inc");
include("dump.inc");

function check_login(user, password, port) {

  local_var soc, req, len, data, res, typ, code, pass, passlen, salt, x;
  global_var concluded;

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
    return;
  }

  res += recv(socket:soc, length:4);
  if (strlen(res) < 5) {
    close(soc);
    return;
  }

  x = substr(res, 1, 4);

  len = ord(x[0]) << 24 | ord(x[1]) << 16 | ord(x[2]) << 8 | ord(x[3]);
  res += recv(socket:soc, length:len);

  if(strlen(res) < len || strlen(res) < 8) {
    close(soc);
    return;
  }

  typ = substr(res, strlen(res)-6,strlen(res)-5);
  typ = ord(typ[1]);

  if(typ != 5) {
    close(soc);
    return;
  }

  salt = substr(res, strlen(res)-4);
  userpass = hexstr(MD5( password + user));
  pass = 'md5' + hexstr(MD5( userpass + salt));

  passlen = strlen(pass) + 5;

  req = string(raw_string(0x70), raw_string((passlen >> 24 ) & 0xff,(passlen >> 16 ) & 0xff, (passlen >>  8 ) & 0xff,(passlen) & 0xff), pass, raw_string(0));
  send(socket:soc, data:req);

  res = recv(socket:soc, length:1);

  if(isnull(res) || res[0] != "R") {
    close(soc);
    return;
  }

  res += recv(socket:soc, length:8);

  if(strlen(res) < 8) {
    close(soc);
    return;
  }

  code = substr(res,5,strlen(res));

  if(res[0] == "R" && hexstr(code) == "00000000") {

    recv(socket:soc, length:65535);

    sql = "select version();";
    sqllen = strlen(sql) + 5;
    slen = raw_string((sqllen >> 24 ) & 0xff,(sqllen >> 16 ) & 0xff, (sqllen >>  8 ) & 0xff,(sqllen) & 0xff);

    req = raw_string(0x51) + slen + sql + raw_string(0x00);
    send(socket:soc, data:req);

    res = recv(socket:soc, length:1);
    if(isnull(res) || res[0] != "T") {
      close(soc);
      return;
    }

    res += recv(socket:soc, length:1024);
    close(soc);

    if("PostgreSQL" >< res && "SELECT" >< res) {
      res = bin2string(ddata:res);
      version = eregmatch(pattern:"PostgreSQL (([0-9.]+)([a-z0-9.]+)?)", string:res);

      if (!isnull(version[1]) && isnull(version[3])) {
        vers = version[1];
      } else if(!isnull(version[2]) && !isnull(version[3])) {
        vers = version[2] + "." + version[3];
      }
    }

     if(vers) {
       concluded = res;
       return vers;
     }

  }

  close(soc);
  return;

}

port = get_kb_item( "Services/postgresql" );
if(! port ) port = 5432; # Default PostgreSQL port
if( ! get_port_state( port ) ) exit( 0 ); # exit if port is not open

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

#user: postgres, database: postgres,client_encoding: unicode,
#datestyle: iso
req = raw_string(0x00,0x00,0x00,0x4f,0x00,0x03,0x00,0x00,0x75,0x73,0x65,0x72,0x00,0x70,0x6f,0x73,
		 0x74,0x67,0x72,0x65,0x73,0x00,0x64,0x61,0x74,0x61,0x62,0x61,0x73,0x65,0x00,0x70,
		 0x6f,0x73,0x74,0x67,0x72,0x65,0x73,0x00,0x63,0x6c,0x69,0x65,0x6e,0x74,0x5f,0x65,
		 0x6e,0x63,0x6f,0x64,0x69,0x6e,0x67,0x00,0x55,0x4e,0x49,0x43,0x4f,0x44,0x45,0x00,
		 0x44,0x61,0x74,0x65,0x53,0x74,0x79,0x6c,0x65,0x00,0x49,0x53,0x4f,0x00,0x00);

send(socket:soc, data:req);
res = recv(socket:soc, length:256);
close(soc);

if (!res || res[0] >!< "(E|R)" ) {
  # The response was empty or does not match typical PostgrSQL
  # elements. Therefore it is concluded this is not PostgreSQL
  # running on this port.
  exit(0);
}

dump = bin2string(ddata:res);
concluded = dump;
b = substr(res, 1, 4);
blen = ord(b[0])/24 | ord(b[1])/16 | ord(b[2])/8 | ord(b[3]);

if ((dump[0] == "E")  &&
    (
    "ERROR"   >< dump ||
    "FATAL"   >< dump ||
    "PANIC"   >< dump ||
    "WARNING" >< dump ||
    "NOTICE"  >< dump ||
    "DEBUG"   >< dump ||
    "INFO"    >< dump ||
    "LOG"     >< dump
    ) ||
    dump[0] == "R" && (blen == 8 || blen == 12)) {
  cpe = "None";

  if (dump[0] == "R") {
    version = eregmatch(pattern:"server_version(([0-9.]+)([a-z0-9.]+)?)", string:dump);

    if (!isnull(version[1]) && isnull(version[3])) {
      vers = version[1];
    } else if(!isnull(version[2]) && !isnull(version[3])) {
      vers = version[2] + "." + version[3];
    }

    if (isnull(vers)) {
      login = script_get_preference("Postgres Username:");
      password = script_get_preference("Postgres Password:");
      if(strlen(login) && strlen(password)) {
        vers = check_login(user:login, password:password, port:port);
      }
    }

    if (!isnull(vers)) {
      set_kb_item(name:"PostgreSQL/Remote/" + port + "/Ver", value:vers);
      set_kb_item(name:"OpenDatabase/found", value:TRUE);
    }
  }

  # In case the service wasn't identified before
  register_service(port:port, proto:"postgresql");

  if (!isnull(vers))
      cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:postgresql:postgresql:");
  else
      cpe = "cpe:/a:postgresql:postgresql";

  if(!vers)vers="unknown";

  register_product(cpe:cpe, location:string(port, "/tcp"), port:port);
  set_kb_item(name:"PostgreSQL/installed", value:TRUE);

  log_message(port:port, data:  build_detection_report(app:"PostgreSQL", version:vers, install:port + '/tcp', cpe:cpe, concluded:vers));
}

exit(0);
