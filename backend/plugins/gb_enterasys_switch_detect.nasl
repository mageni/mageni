###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_enterasys_switch_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Enterasys Device Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105600");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-08 12:19:03 +0200 (Fri, 08 Apr 2016)");
  script_name("Enterasys Device Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Enterasys devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("enterasys/detected", "ssh/login/uname");
  exit(0);
}

include("host_details.inc");

uname = get_kb_item("ssh/login/uname");
if( ! uname || 'Error: Unknown: "/bin/sh"' >!< uname ) exit( 0 );

cpe = 'cpe:/h:enterasys:enterasys';
vers = 'unknown';

version = eregmatch( pattern:'Chassis Firmware Revision:\\s*([0-9.]+[^\r\n]+)', string:uname );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  cpe += ':' + vers;
}

register_product( cpe:cpe, location:'ssh' );

report = 'The remote host seems to be an Enterasys device';
if( vers ) report += '\nFirmware version: ' + vers;
report += '\nCPE: ' + cpe + '\n';

log_message( port:0, data:report );
exit( 0 );

