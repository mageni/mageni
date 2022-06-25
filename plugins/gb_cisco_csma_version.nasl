###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_csma_version.nasl 10033 2018-05-31 07:51:19Z ckuersteiner $
#
# Cisco Content Security Management Appliance Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105433");
  script_version("$Revision: 10033 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-31 09:51:19 +0200 (Thu, 31 May 2018) $");
  script_tag(name:"creation_date", value:"2015-11-06 12:16:22 +0100 (Fri, 06 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Cisco Content Security Management Appliance Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ironport_csma_detect.nasl", "gather-package-list.nasl");
  script_mandatory_keys("cisco_csm/installed");

  script_tag(name:"summary", value:"This Script get the via HTTP(s) or SSH detected Cisco Content Security
Management Appliance version");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

source = 'SSH';

version = get_kb_item("cisco_csm/version/ssh");
if( ! version )
{
  version = get_kb_item("cisco_csm/version/http");
  source = 'HTTP(s)';
}

if( ! version ) exit( 0 );

model = get_kb_item("cisco_csm/model/ssh");
if( ! model ) model = get_kb_item("cisco_csm/model/http");

set_kb_item( name:"cisco_csm/version", value:version );

if( model ) set_kb_item( name:"cisco_csm/model", value:model );

cpe = 'cpe:/h:cisco:content_security_management_appliance:' + version;

register_product( cpe:cpe );
register_and_report_os( os:"Cisco AsyncOS", cpe:"cpe:/o:cisco:asyncos:" + version, banner_type:source, desc:"Cisco Content Security Management Appliance Detection", runs_key:"unixoide" );

report = 'Detected Cisco Content Security Management Appliance\nVersion: ' + version + '\nCPE: ' + cpe;
if( model ) report += '\nModel: ' + model;

report += '\nDetection source: ' + source;

log_message( port:0, data:report );
exit( 0 );

