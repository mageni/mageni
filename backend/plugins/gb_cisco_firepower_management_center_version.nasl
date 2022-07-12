###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Firepower Management Center Version Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105522");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-01-19 18:05:56 +0100 (Tue, 19 Jan 2016)");
  script_name("Cisco Firepower Management Center Version Detection");

  script_tag(name:"summary", value:"This script get the version of Cisco Firepower Management Center detected via SSH or HTTP");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_ssh_detect.nasl", "gb_cisco_firepower_management_center_web_detect.nasl");
  script_mandatory_keys("cisco_fire_linux_os/installed");
  exit(0);
}


include("host_details.inc");

source = 'ssh';

version = get_kb_item( "cisco/firepower/" + source + "/version" );
if( ! version )
{
  source = 'http';
  version = get_kb_item( "cisco/firepower/" + source + "/version" );
  if( ! version ) exit( 0 );
}

set_kb_item( name:"cisco_firepower_management_center/version", value:version );
rep_version = version;

build = get_kb_item( "cisco/firepower/" + source + "/build");
if( build )
{
  set_kb_item( name:"cisco_firepower_management_center/build", value:build );
  rep_version += ' (Build: ' + build +  ' )';
}

model =  get_kb_item( "cisco/firepower/" + source + "/model");
if( model ) set_kb_item( name:"cisco_firepower_management_center/model", value:model );

cpe = 'cpe:/a:cisco:firepower_management_center:' + version;

register_product( cpe:cpe, location:source );

log_message( data: build_detection_report( app:'Cisco FirePOWER Management Center',
                                           version:rep_version ,
                                           install:source,
                                           cpe:cpe,
                                           concluded:source  ),
             port:0 );

exit( 0 );

