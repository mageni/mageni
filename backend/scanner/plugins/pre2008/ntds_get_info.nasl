###############################################################################
# OpenVAS Vulnerability Test
# $Id: ntds_get_info.nasl 9377 2018-04-06 10:03:08Z cfischer $
#
# Use LDAP search request to retrieve information from NT Directory Services
#
# Authors:
# David Kyger <david_kyger@symantec.com>
# changes by rd: minor wording in the description
#
# Copyright:
# Copyright (C) David Kyger
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
  script_oid("1.3.6.1.4.1.25623.1.0.12105");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Use LDAP search request to retrieve information from NT Directory Services");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Kyger");
  script_family("Remote file access");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"It is possible to disclose LDAP information.

  Description :

  The directory base of the remote server is set to NULL. This allows information
  to be enumerated without any prior knowledge of the directory structure.");
  script_tag(name:"solution", value:"If pre-Windows 2000 compatibility is not required, remove
  pre-Windows 2000 compatibility as follows :

  - start cmd.exe

  - execute the command :
    net localgroup  'Pre-Windows 2000 Compatible Access' everyone /delete

  - restart the remote host");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("ldap.inc");
include("misc_func.inc");

port = get_ldap_port( default:389 );
if( is_ldapv3( port:port ) )
  exit( 0 );

senddata = raw_string(
0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a,
0x01, 0x00, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65,
0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00
			);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

send( socket:soc, data:senddata );
buf = recv( socket:soc, length:4096 );
close( soc );
version = string( buf );

if(!buf)
  exit(0);

if ("NTDS" >< buf) {
  hbuf = hexstr( buf );
  ntdsinfo = strstr(hbuf, "4e54445320");
  ntdsinfo = ntdsinfo - strstr(ntdsinfo, "308400");
  ntdsinfo = hex2raw(s:ntdsinfo);
  warning += string(ntdsinfo,"\n\n");

  report = string( "The following information was pulled from the server via a LDAP request:\n", warning );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );