###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_version.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Report Cisco IOS XE Software Version
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105659");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-05-09 15:46:47 +0200 (Mon, 09 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Report Cisco IOS XE Software Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_os_detection.nasl", "gb_cisco_ios_xe_version_ssh.nasl");
  script_mandatory_keys("cisco_ios_xe/detected");

  script_tag(name:"summary", value:"Report the Cisco IOS XE Software Version.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

cpe = 'cpe:/o:cisco:ios_xe';
version = 'unknown';

source = "ssh";

if( ! version = get_kb_item("cisco_ios_xe/" + source + "/version") )
{
  source = "snmp";
  if( ! version = get_kb_item("cisco_ios_xe/" + source + "/version") ) exit( 0 );
}

if( ! isnull( version ) )
{
  cpe += ':' + version;
  set_kb_item( name:'cisco_ios_xe/version', value:version );
}

if( model = get_kb_item( "cisco_ios_xe/" + source + "/model")  )
{
  set_kb_item( name:'cisco_ios_xe/model', value:model );
}

if( image = get_kb_item( "cisco_ios_xe/" + source + "/image")  )
{
  set_kb_item( name:'cisco_ios_xe/image', value:image );
}

register_product( cpe:cpe, location:source );
register_and_report_os( os:"Cisco IOS XE", cpe:cpe, banner_type:toupper( source ), desc:"Report Cisco IOS XE Software Version", runs_key:"unixoide" );

report = 'Detected Cisco IOS XE\n' +
         'Version: ' + version + '\n' +
         'CPE: ' + cpe + '\n';

if( model ) report += 'Model:   ' + model + '\n';
if( image ) report += 'Image:   ' + image + '\n';

report += 'Detection source: ' + source + '\n';

log_message( port:0, data:report );
exit( 0 );

