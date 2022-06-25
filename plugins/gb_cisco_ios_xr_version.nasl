###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_version.nasl 5709 2017-03-24 08:56:58Z cfi $
#
# Cisco IOS XR Version Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105532");
  script_version("$Revision: 5709 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-24 09:56:58 +0100 (Fri, 24 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-01-27 10:46:32 +0100 (Wed, 27 Jan 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cisco IOS XR Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_detect_snmp.nasl", "gb_cisco_ios_xr_version_ssh.nasl");
  script_mandatory_keys("cisco_ios_xr/detected");

  script_tag(name:"summary", value:"This script get the version of Cisco IOS XR detected via SSH or SNMP");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

source = 'ssh';

version = get_kb_item( "cisco_ios_xr/" + source + "/version" );
if( ! version )
{
  source = 'snmp';
  version = get_kb_item( "cisco_ios_xr/" + source + "/version" );
  if( ! version ) exit( 0 );
}

set_kb_item( name:"cisco/ios_xr/version", value:version );
set_kb_item( name:"cisco/ios_xr/detection_source", value:source );

model =  get_kb_item( "cisco_ios_xr/" + source + "/model" );
if( model ) set_kb_item( name:"cisco/ios_xr/model", value:model );

cpe = 'cpe:/o:cisco:ios_xr:' + version;

register_product( cpe:cpe, location:source );

register_and_report_os( os:"Cisco IOS XR", cpe:cpe, banner_type:toupper( source ), desc:"Cisco IOS XR Version Detection", runs_key:"unixoide" );

log_message( data: build_detection_report( app:'Cisco IOS XR',
                                           version:version ,
                                           install:source,
                                           cpe:cpe,
                                           concluded:source  ),
             port:0 );

exit( 0 );

