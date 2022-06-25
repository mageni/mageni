###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_management_center_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco FireSIGHT Management Center Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105427");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-10-29 13:14:47 +0100 (Thu, 29 Oct 2015)");
  script_name("Cisco FireSIGHT Management Center Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco FireSIGHT Management Center");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("sourcefire_linux_os/installed");
  exit(0);
}


include("host_details.inc");
include("ssh_func.inc");

if( ! get_kb_item( "sourcefire_linux_os/installed" ) ) exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

sf_version = ssh_cmd( socket:sock, cmd:"cat /etc/sf/sf-version" );

close( sock );

if( "Defense Center" >!< sf_version ) exit( 0 );

cpe = 'cpe:/a:cisco:firesight_management_center';

if( "/ Sourcefire Linux OS" >< sf_version )
{
  sf = split( sf_version, sep:"/", keep:FALSE );
  if( ! isnull( sf[0] ) ) sf_version = sf[0];
}

vb = eregmatch( pattern:'v([^ ]+) \\(build ([^)]+)\\)', string:sf_version );

rep_version = 'unknown';

if( ! isnull( vb[1] ) )
{
  version = vb[1];
  cpe += ':' + version;
  set_kb_item( name:"cisco_firesight_management_center/version", value:version );
  rep_version = version;
}

if( ! isnull( vb[2] ) )
{
  build = vb[2];
  set_kb_item( name:"cisco_firesight_management_center/build", value:build );
  rep_version += ' (build ' + build + ')';
}

register_product( cpe:cpe, location:'ssh' );

if( "Virtual Defense Center" >< sf_version )
  model = "VM";
else
{
  ms = sf_version;
  ms = ereg_replace( string:ms, pattern:'(32|64)bit', replace:'' );
  _m = eregmatch( pattern:'Defense Center ([^ v]+) v', string:ms );
  if( ! isnull( _m[1] ) ) model = _m[1];
}

if( model )
{
  set_kb_item( name:"cisco_firesight_management_center/model", value:model );
  rep_model = 'Model: ' + model + '\n';
}

log_message( data: build_detection_report( app:'Cisco FireSIGHT Management Center',
                                           version:rep_version,
                                           install:'ssh',
                                           cpe:cpe,
                                           extra: rep_model,
                                           concluded: sf_version ),
             port:0 );

exit( 0 );

