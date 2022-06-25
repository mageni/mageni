# OpenVAS Vulnerability Test
# $Id: sybase_blank_password.nasl 14010 2019-03-06 08:24:33Z cfischer $
# Description: Sybase SQL Blank Password
#
# Authors:
# Tenable Network Security
# This script is based on mssql_blank_password.nasl which is (C) H D Moore
#
# Copyright:
# Copyright (C) 2008 Tenable Network Security
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = 'cpe:/a:sybase:adaptive_server_enterprise';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80018");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-24 19:51:47 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sybase SQL Blank Password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2008 Tenable Network Security");
  script_family("Databases");
  script_require_ports("Services/sybase", 5000);
  script_dependencies("gb_sybase_tcp_listen_detect.nasl");
  script_mandatory_keys("sybase/tcp_listener/detected");

  script_tag(name:"solution", value:"Either disable this account or set a password for it.");

  script_tag(name:"summary", value:"The remote Sybase SQL server has the default 'sa' account
  enabled without any password.");

  script_tag(name:"impact", value:"An attacker may use this flaw to execute commands against the
  remote host as well as read database content.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("sybase_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"sybase_tcp_listener" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

found = 0;

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

# this creates a variable called sql_packet
sql_packet = make_sql_login_pkt(username:"sa", password:"");

send(socket:soc, data:sql_packet);
send(socket:soc, data:pkt_lang);
r = recv(socket:soc, length:255);
close(soc);

if(strlen(r) > 10 && ord(r[8]) == 0xE3) {

  version = substr(r, strlen(r) - 13, strlen(r) - 10 );
  strver = NULL;
  for ( i = 0 ; i < 4; i++ )
  {
    if ( strver) strver += '.';
    strver += ord(version[i]);
  }

  set_kb_item(name:"sybase/version", value:strver);
  security_message(port:port);

  cpe = build_cpe(value:strver, exp:"^([0-9.]+)", base:"cpe:/a:sybase:adaptive_server_enterprise:");
  if(cpe)
    register_host_detail(name:"App", value:cpe, desc:"Sybase SQL Blank Password");
}

exit( 0 );