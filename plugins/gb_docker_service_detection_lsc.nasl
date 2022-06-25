###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_docker_service_detection_lsc.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Docker Service Detection (LSC)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140119");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-11 15:14:18 +0100 (Wed, 11 Jan 2017)");
  script_name("Docker Service Detection (LSC)");
  script_tag(name:"summary", value:"This script performs ssh based detection of Docker");
  script_tag(name:"qod_type", value:"package");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("gather-package-list-docker-container.inc");

soc = ssh_login_or_reuse_connection();
if( ! soc ) exit( 0 );

buf = ssh_cmd( socket:soc, cmd:"docker info" );

if( "Containers" >!< buf || "Images" >!< buf )
{
  close( soc );
  exit( 0 );
}

set_kb_item( name:'docker/info', value:buf );

cpe = 'cpe:/a:docker:docker';

version = 'unknown';

v = eregmatch( pattern:'Server Version: ([0-9.]+[^\r\n]+)', string:buf );
if( isnull( v[1] ) )
{
  buf = ssh_cmd( socket:soc, cmd:"docker version" );
  if( buf )
  {
    set_kb_item( name:"docker/docker_version", value:buf );
    v = eregmatch( pattern:'Server version: ([0-9.]+[^\r\n]+)', string:buf );

    if( isnull( v[1] ) )
      v = eregmatch( pattern:'Server:[ \r\n]*Version:\\s*([0-9.]+[^\r\n]+)', string:buf );
  }
}

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  replace_kb_item( name:"docker/version", value:version );
}

register_product( cpe:cpe, location:'ssh', port:0 );

buf = ssh_cmd( socket:soc, cmd:"docker ps -a --no-trunc" );

if( buf =~ "^CONTAINER ID" )
{
  lines = split( buf );
  containers = make_array();

  foreach line ( lines )
  {
    if( line !~ "^[0-9a-f]{64}" ) continue;

    line = ereg_replace( pattern:'([^a-zA-Z0-9_-]+\\s[^a-zA-Z0-9_])', string:line, replace:"<->", icase:TRUE );

    parts = split( line, sep:'<->', keep:FALSE );

    if( max_index( parts ) != 6 && max_index( parts ) != 7 ) continue;

    id    = chomp( parts[0] );
    name  = chomp( parts[ ( max_index( parts ) - 1 ) ] );
    image = chomp( parts[1] );

    if( max_index( parts ) == 6 )
    {
      ports = "N/A";
      state = chomp( chomp( parts[ ( max_index( parts ) - 2 ) ] ) );
    }
    else
    {
      ports = chomp( chomp( parts[ ( max_index( parts ) - 2 ) ] ) );
      state = chomp( chomp( parts[ ( max_index( parts ) - 3 ) ] ) );
    }

    if( ! id || ! name || ! image ) continue;

    set_kb_item( name:'docker/lsc/container/' + id + '/id',    value:id );
    set_kb_item( name:'docker/lsc/container/' + id + '/name',  value:name );
    set_kb_item( name:'docker/lsc/container/' + id + '/image', value:image );
    set_kb_item( name:'docker/lsc/container/' + id + '/ports', value:ports );
    set_kb_item( name:'docker/lsc/container/' + id + '/state', value:state );

    if( state !~ "^Up " ) continue;

    cdata += "Name:  " + name  + '\n' +
             "ID:    " + id    + '\n' +
             "Image  " + image + '\n';

    os_array = get_container_os( container_id:id, soc:soc );

    if( os_array['OS'] )
      cdata += "OS     " + os_array['OS'] + '\n';
    else
       cdata += 'OS:    Unknown\n';

    if( os_array['OS-CPE'] )
      cdata += "CPE:   " + os_array['OS-CPE'] + '\n';

    cdata += "Ports: " + ports + '\n';

    cdata += '\n';
  }
}

close( soc );

report = build_detection_report( app:'Docker', version:version, install:'ssh', cpe:cpe, concluded:v[0] );

if( cdata )
{
  set_kb_item( name:"docker/container/present", value:TRUE );
  report += '\nThe following containers where detected running on the remote host:\n\n' + cdata;
}

log_message( port:0, data:report );

exit( 0 );

