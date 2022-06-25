###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_mse_cmx_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Mobility Services Engine Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105459");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-19 16:21:45 +0100 (Thu, 19 Nov 2015)");
  script_name("Cisco Mobility Services Engine Detection");

  script_tag(name:"summary", value:"This Script get the via SSH detected Cisco Mobility Services Engine version");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_mse_cmx_web_iface_detect.nasl", "gb_cisco_mse_cmx_ssh_detect.nasl");
  script_mandatory_keys("cisco_mse/lsc");
  exit(0);
}


include("host_details.inc");

cpe = 'cpe:/a:cisco:mobility_services_engine';
source = 'SSH';

version = get_kb_item( "cisco_mse/ssh/version" );

if( ! version )
{
  source = 'HTTP(s)';
  version = get_kb_item( "cisco_mse/http/version" );
}

if( ! version ) exit( 0 );

version = str_replace( string:version, find:"-", replace:"." );

cpe += ':' + version;
set_kb_item( name:"cisco_mse/version", value:version );

register_product( cpe:cpe );

report = 'Detected Cisco Mobility Service Engine\nVersion: ' + version + '\nCPE: ' + cpe + '\nDetection source: ' + source;

log_message( port:0, data:report );
exit( 0 );

