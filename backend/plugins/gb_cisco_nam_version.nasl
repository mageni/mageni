###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_nam_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco Network Analysis Module Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105457");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-11-18 12:57:00 +0100 (Wed, 18 Nov 2015)");
  script_name("Cisco Network Analysis Module Detection");

  script_tag(name:"summary", value:"This Script get the via SSH detected Cisco Network Analysis Module version");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco_nam/show_ver");
  exit(0);
}


include("host_details.inc");

show_ver = get_kb_item("cisco_nam/show_ver");

if( ! show_ver || "NAM application image version" >!< show_ver ) exit( 0 );

vers = 'unknown';
patch = 0 ;

cpe = 'cpe:/o:cisco:network_analysis_module_firmware';

set_kb_item( name:"cisco_nam/installed", value:TRUE );

version = eregmatch( pattern:'NAM application image version: ([^\r\n]+)', string:show_ver );

if( ! isnull( version[1] ))
{
  if( "-patch" >< version[1] )
  {
    v = split( version[1], sep:"-", keep:FALSE );
    if( ! isnull( v[0] ) )
      vers = str_replace( string:v[0], find:"(", replace:".");

    if( ! isnull( v[1] ) )
    {
      p = eregmatch( pattern:'patch([0-9]+)', string:v[1] );
      if( ! isnull( p[1] ) ) patch =  p[1];
    }
  }
  else
  {
    vers = ereg_replace( string:version[1], pattern:"[()]+", replace:"." );
  }
}

if( vers != "unknown" )
{
  vers =  ereg_replace( string:vers, pattern:'\\.$', replace:"" );
  cpe += ':' + vers;
  set_kb_item( name:"cisco_nam/version", value:vers );
}

set_kb_item( name:"cisco_nam/patch", value:patch );

pid = eregmatch( pattern:'PID: ([^\r\n]+)', string:show_ver );

if( ! isnull( pid[1] ) )
{
  if( "ESX" >< pid[1] ) set_kb_item( name:"cisco_nam/vnam", value:TRUE);

  set_kb_item( name:"cisco_nam/pid", value:pid[1] );
}

register_product( cpe:cpe );

report = 'Detected Cisco Network Analysis Module\nVersion: ' + vers + '\nCPE: ' + cpe;

log_message( port:0, data:report );
exit( 0 );

