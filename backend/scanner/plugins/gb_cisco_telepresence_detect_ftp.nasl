###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_telepresence_detect_ftp.nasl 13499 2019-02-06 12:55:20Z cfischer $
#
# Cisco TelePresence Detection (FTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103891");
  script_version("$Revision: 13499 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-06 13:55:20 +0100 (Wed, 06 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-01-27 13:32:54 +0100 (Mon, 27 Jan 2014)");
  script_name("Cisco TelePresence Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "gb_cisco_telepresence_detect_snmp.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/cisco/telepresence/detected");
  script_exclude_keys("cisco/telepresence/version", "cisco/telepresence/typ"); # already detected by gb_cisco_telepresence_detect_snmp.nasl

  script_tag(name:"summary", value:"The script sends a connection request to
  the server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");

if( get_kb_item ( "cisco/telepresence/typ" ) ) {
  if( get_kb_item ( "cisco/telepresence/version" ) ) exit( 0 );
}

cisport = get_ftp_port( default:21 );
banner = get_ftp_banner( port:cisport );
if( ! banner || banner !~ 'Welcome to the (Cisco TelePresence|Codian) MCU' ) exit( 0 );

typ = 'unknown';
t = eregmatch( pattern:'((Cisco TelePresence|Codian) MCU [^,]+)', string:banner );
if( ! isnull( t[1] ) )
  typ = t[1];

version = 'unknown';
s = eregmatch( pattern:', version (.*)$', string:banner );
if( ! isnull( s[1] ) )
  version = chomp ( s[1] );

set_kb_item( name:"cisco/telepresence/typ", value:typ );
set_kb_item( name:"cisco/telepresence/version", value:version );

cpe = 'cpe:/a:cisco:telepresence_mcu_mse_series_software:' + tolower( version );

register_product( cpe:cpe, location:cisport + '/tcp', port:cisport, service:"ftp" );
log_message( data:build_detection_report( app:typ,
                                          version:version,
                                          install:cisport + '/tcp',
                                          cpe:cpe,
                                          concluded:banner ),
             port:cisport );

exit( 0 );