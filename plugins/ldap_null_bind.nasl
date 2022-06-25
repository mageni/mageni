###############################################################################
# OpenVAS Vulnerability Test
# $Id: ldap_null_bind.nasl 10905 2018-08-10 14:32:11Z cfischer $
#
# LDAP allows anonymous binds
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
  script_oid("1.3.6.1.4.1.25623.1.0.10723");
  script_version("$Revision: 10905 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("LDAP allows anonymous binds");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2000 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"solution", value:"Disable NULL BIND on your LDAP server");
  script_tag(name:"summary", value:"It is possible to disclose LDAP information.

  Description :

  Improperly configured LDAP servers will allow any user to connect to the
  server via a NULL BIND and query for information.

  NULL BIND is required for LDAPv3. Therefore this Plugin will not run
  against LDAPv3 servers.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ldap.inc");

port = get_ldap_port( default:389 );

string = raw_string( 0x30, 0x0C, 0x02, 0x01, 0x01, 0x60,
                     0x07, 0x02, 0x01, 0x02, 0x04, 0x00,
                     0x80,0x80 );

if( is_ldapv3( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

send( socket:soc, data:string );
result = recv( socket:soc, length:4096 );
close( soc );

if( result && ! isnull( result ) && strlen( result ) > 6 ) {
  error_code = substr( result, strlen( result ) - 7, strlen( result ) - 5 );
  if( hexstr( error_code ) == "0a0100" ) {
    security_message( port:port );
    set_kb_item( name:"LDAP/" + port + "/NULL_BIND", value:TRUE );
    exit( 0 );
  }
}

exit( 99 );
