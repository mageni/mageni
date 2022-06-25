###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nx_os_version.nasl 10899 2018-08-10 13:49:35Z cfischer $
#
# Report Cisco NX-OS Software Version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105690");
  script_version("$Revision: 10899 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:49:35 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-05-12 12:21:43 +0200 (Thu, 12 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Report Cisco NX-OS Software Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_cisco_nx_os_detect.nasl", "gb_cisco_nx_os_detect_ssh.nasl");
  script_mandatory_keys("cisco/nx_os/detected");

  script_tag(name:"summary", value:"Report the Cisco NX-OS Software Version.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");

cpe = 'cpe:/o:cisco:nx-os';
version = 'unknown';

source = "ssh";

if( ! version = get_kb_item("cisco/nx_os/" + source + "/version") )
{
  source = "snmp";
  if( ! version = get_kb_item("cisco/nx_os/" + source + "/version") ) exit( 0 );
}

if( ! isnull( version ) )
{
  cpe += ':' + version;
  set_kb_item( name:'cisco_nx_os/version', value:version );
}

if( model = get_kb_item( "cisco/nx_os/" + source + "/model" )  )
{
  if( model == "MDS" ) model = "unknown";
  set_kb_item( name:'cisco_nx_os/model', value:model );
}

if( device = get_kb_item( "cisco/nx_os/" + source + "/device")  )
{
  set_kb_item( name:'cisco_nx_os/device', value:device );
}

register_product( cpe:cpe, location:source );
register_and_report_os( os:"Cisco NX OS", cpe:cpe, banner_type:toupper( source ), desc:"Report Cisco NX-OS Software Version", runs_key:"unixoide" );

report = 'Detected Cisco NX-OS\n' +
         'Version: ' + version + '\n' +
         'CPE:     ' + cpe + '\n';

if( model ) report += 'Model:   ' + model + '\n';
if( device ) report += 'Typ:     ' + device + '\n';

report += 'Detection source: ' + source + '\n';

log_message( port:0, data:report );
exit( 0 );

