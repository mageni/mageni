###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerisystems_access_control_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Keri Systems Access Control Systems Detection
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105418");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-21 16:57:28 +0200 (Wed, 21 Oct 2015)");
  script_name("Keri Systems Access Control Systems Detection");

  script_tag(name:"summary", value:"This script performs telnet banner based idetection of Keri Systems Access Control systems");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/keri_systems/access_control_system/detected");

  exit(0);
}

include("misc_func.inc");
include("telnet_func.inc");

port = get_telnet_port( default:23 );
if( ! banner = get_telnet_banner( port:port ) ) exit( 0 );
if( "KERI-ENET" >!< banner ) exit( 0 );

version = eregmatch( pattern:'Software version V([^ ]+)( \\(([0-9]+)\\))?', string:banner );

if( ! isnull(version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"keri_systems_access_control/version", value:vers );
}

if( ! isnull(version[3] ) )
{
  build = version[3];
  set_kb_item( name:"keri_systems_access_control/build", value:build );
}

_aes = eregmatch( pattern:'AES library version ([^\r\n]+)', string:banner );
if( ! isnull( _aes[1] ) )
{
  aes = _aes[1];
  set_kb_item( name:"keri_systems_access_control/aes_version", value:aes );
}

report = 'The remote host seems to be running a Keri Systems Access Control system' + '\n';

if( vers ) report += 'Version: ' + vers;
if( build) report += ' (' + build + ')\n';
if( aes ) report += 'AES library version: ' + aes;

log_message( port:port, data:report );
exit( 0 );

