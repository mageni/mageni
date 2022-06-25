###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_version_ssh.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco IOS XR Detection (SSH)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105530");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-26 17:59:41 +0100 (Tue, 26 Jan 2016)");
  script_name("Cisco IOS XR Detection (SSH)");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco IOS XR");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_show_version.nasl");
  script_mandatory_keys("cisco/show_version");
  exit(0);
}

source = "ssh";

if( ! system = get_kb_item( "cisco/show_version" ) ) exit( 0 );

if( ! egrep( pattern:"^.* IOS[ -]XR Software.*Version [0-9]+\.[0-9.]+", string:system ) ) exit( 0 );

set_kb_item( name:"cisco_ios_xr/detected", value:TRUE );

vers = 'unknown';
cpe = 'cpe:/o:cisco:ios_xr';

version = eregmatch( pattern:", *Version +([0-9]+\.[0-9.]+)", string:system );

if( ! isnull( version[1] ) )
{
  vers = version[1];
  set_kb_item( name:"cisco_ios_xr/" + source + "/version", value:vers );
  cpe += ':' + vers;
}

hardware = eregmatch( pattern:"cisco ([^(]+) \([^)]+\) processor", string:system );

if( ! isnull( hardware[1] ) )
{
   hw = hardware[1];
   set_kb_item( name:"cisco_ios_xr/" + source + "/model", value:hw );
}

chassis = eregmatch(pattern: "([A-Za-z 0-9-]+) Chassis", string:system);
if (!isnull(chassis[1])) {
  chass = chassis[1];
  set_kb_item(name: "cisco_ios_xr/ssh/chassis", value:chass);
}

report = 'Detected Cisco IOS XR (ssh)\n\n' +
         'Version: ' + vers + '\n';

if( hw )
  report += 'Model:   ' + hw + '\n';

if (chass)
  report += 'Chassis: ' + chass + '\n';

report += 'CPE:     ' + cpe;

log_message( port:0, data:report );

exit( 0 );

