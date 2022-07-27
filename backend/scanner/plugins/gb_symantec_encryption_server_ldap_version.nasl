###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_encryption_server_ldap_version.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# Symantec Encryption Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105559");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-02-24 13:49:24 +0100 (Wed, 24 Feb 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Symantec Encryption Server Detection (LDAP)");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"This script performs LDAP based detection of Symantec Encryption Server");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("dump.inc");
include("ldap.inc");

port = get_ldap_port( default:389 );

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

# ldapsearch -h xxx.xxx.xxx.xxx -x -b "cn=pgpServerInfo" pgpSoftware pgpVersion
req = raw_string(0x30, 0x4e, 0x02, 0x01, 0x02, 0x63, 0x49, 0x04, 0x10, 0x63, 0x6e, 0x3d, 0x70, 0x67, 0x70, 0x53,
                 0x65, 0x72, 0x76, 0x65, 0x72, 0x49, 0x6e, 0x66, 0x6f, 0x0a, 0x01, 0x02, 0x0a, 0x01, 0x00, 0x02,
                 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
                 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x19, 0x04, 0x0b, 0x70, 0x67, 0x70, 0x53, 0x6f, 0x66, 0x74,
                 0x77, 0x61, 0x72, 0x65, 0x04, 0x0a, 0x70, 0x67, 0x70, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e);

send( socket:soc, data:req );

recv = recv( socket:soc, length:512 );
close( soc );

if( "pgpVersion" >!< recv || "PGPServerInfo" >!< recv || "PGP Universal Server" >!< recv ) exit( 0 );

set_kb_item( name:"symantec_encryption_server/installed", value:TRUE );
cpe = 'cpe:/a:symantec:encryption_management_server';

resp = bin2string( ddata:recv, noprint_replacement:' ' );

version = eregmatch( pattern:"pgpVersion[^ ]*[ ]+([0-9.]+) \(", string:resp );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"symantec_encryption_server/ldap/version", value:vers );
  cpe += ':' + vers;
}

_build = eregmatch( pattern:"pgpVersion[^ ]*[ ]+[0-9.]+ \(Build ([0-9]+)\)", string:resp );
if( ! isnull( _build[1] ) )
{
  build = _build[1];
  set_kb_item( name:"symantec_encryption_server/ldap/build", value:build );
}

report = 'Detected Symantec Encryption Server\n';

if( vers ) report += 'Version: ' + vers + '\n';
if( build) report += 'Build  : ' + build + '\n';

report += 'CPE: ' + cpe + '\n';

log_message( port:port, data:report );
exit( 0 );

