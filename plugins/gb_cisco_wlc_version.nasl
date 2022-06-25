###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_wlc_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Wireless LAN Controller Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105430");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-30 14:22:49 +0100 (Fri, 30 Oct 2015)");

  script_name("Cisco Wireless LAN Controller Detection");

  script_tag(name:"summary", value:"This Script get the via SNMP or SSH detected WLC version");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_wlc_detect_snmp.nasl", "gb_cisco_wlc_ssh_version.nasl");
  script_mandatory_keys("cisco_wlc/detected");

  exit(0);
}

include("host_details.inc");

source = 'SSH';

version = get_kb_item("cisco_wlc/version/ssh");
if( ! version )
{
  version = get_kb_item("cisco_wlc/version/snmp");
  source = 'SNMP';
}

if( ! version ) exit( 0 );

model = get_kb_item("cisco_wlc/model/ssh");
if( ! model ) model = get_kb_item("cisco_wlc/model/snmp");

set_kb_item( name:"cisco_wlc/version", value:version );

if( model ) set_kb_item( name:"cisco_wlc/model", value:model );

cpe = 'cpe:/o:cisco:wireless_lan_controller_software:' + version;

register_product( cpe:cpe );

report = 'Detected Cisco Wireless LAN Controller\nVersion: ' + version + '\nCPE: ' + cpe;
if( model ) report += '\nModel: ' + model;

report += '\nDetection source: ' + source;

log_message( port:0, data:report );
exit( 0 );
