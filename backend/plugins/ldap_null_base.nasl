###############################################################################
# OpenVAS Vulnerability Test
# $Id: ldap_null_base.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# LDAP allows null bases
#
# Authors:
# John Lampe (j_lampe@bellsouth.net)
#
# Copyright:
# Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.10722");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("LDAP allows null bases");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"solution", value:"Disable NULL BASE queries on your LDAP server");
  script_tag(name:"summary", value:"It is possible to disclose LDAP information.

  Description :

  Improperly configured LDAP servers will allow the directory BASE
  to be set to NULL. This allows information to be culled without
  any prior knowledge of the directory structure.  Coupled with a
  NULL BIND, an anonymous user can query your LDAP server using a
  tool such as 'LdapMiner'");

  script_tag(name:"qod_type", value:"remote_probe");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("ldap.inc");

string1 = raw_string( 0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x02, 0x04, 0x00, 0x80, 0x80 );
string2 = raw_string( 0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0A, 0x01, 0x00, 0x0A, 0x01, 0x00, 0x02,
                      0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0B, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74,
                      0x63, 0x6C, 0x61, 0x73, 0x73, 0x30, 0x00 );
mystring = string( string1, string2 );

port = get_ldap_port( default:389 );

soc = open_sock_tcp(port);
if( ! soc ) exit( 0 );

send( socket:soc, data:mystring );
rez = recv( socket:soc, length:4096 );
close( soc );

l = strlen( rez );
if( l >= 7 ) {

  error_code = substr( rez, l - 7, l - 5 );

  if( hexstr( error_code ) == "0a0100" ) {
    security_message( port:port );
    set_kb_item( name:"LDAP/" + port + "/NULL_BASE", value:TRUE );
    exit( 0 );
  }
}

exit( 99 );