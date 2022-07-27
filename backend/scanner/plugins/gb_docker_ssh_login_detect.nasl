# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140119");
  script_version("2021-04-21T07:59:45+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-01-11 15:14:18 +0100 (Wed, 11 Jan 2017)");
  script_name("Docker Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of Docker.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");
include("version_func.inc");
include("gather-package-list-docker-container.inc");

soc = ssh_login_or_reuse_connection();
if( ! soc )
  exit( 0 );

cmd = "docker info";
# nb: Errors needs to be returned for the second ": permission denied" string below.
buf = ssh_cmd( socket:soc, cmd:cmd, return_errors:TRUE, return_linux_errors_only:TRUE );
if( ! buf ) {
  close( soc );
  exit( 0 );
}

# e.g.:
# Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?
#
# Got permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get http://%2Fvar%2Frun%2Fdocker.sock/v1.26/info: dial unix /var/run/docker.sock: connect: permission denied
if( "Cannot connect to the Docker daemon at" >< buf ||
    "Got permission denied while trying to connect to the Docker daemon" >< buf ) {
  not_running_or_no_perms = TRUE;
  extra  = 'Not possible to run the command "' + cmd + '" due to the following message:\n\n- ' + chomp( buf ) + '\n\n';
  extra += 'Information gathering on running docker containers not possible. Please either start ';
  extra += 'the docker daemon or assign the related permissions to the scanning user.';
} else if( "Containers" >< buf && "Images" >< buf ) {
  docker_info_accessible = TRUE;
} else {
  close( soc );
  exit( 0 );
}

if( docker_info_accessible ) {

  set_kb_item( name:"docker/info", value:buf );

  v = eregmatch( pattern:'Server Version: ([0-9.]+[^\r\n]+)', string:buf );
  if( isnull( v[1] ) ) {
    buf = ssh_cmd( socket:soc, cmd:"docker version" );
    if( buf ) {
      set_kb_item( name:"docker/docker_version", value:buf );
      v = eregmatch( pattern:'Server version: ([0-9.]+[^\r\n]+)', string:buf );

      if( isnull( v[1] ) )
        v = eregmatch( pattern:'Server:[ \r\n]*Version:\\s*([0-9.]+[^\r\n]+)', string:buf );
    }
  }

  buf = ssh_cmd( socket:soc, cmd:"docker ps -a --no-trunc" );

  if( buf =~ "^CONTAINER ID" ) {

    lines = split( buf );
    containers = make_array();

    foreach line( lines ) {

      if( line !~ "^[0-9a-f]{64}" )
        continue;

      line = ereg_replace( pattern:"([^a-zA-Z0-9_-]+\s[^a-zA-Z0-9_])", string:line, replace:"<->", icase:TRUE );

      parts = split( line, sep:"<->", keep:FALSE );

      if( max_index( parts ) != 6 && max_index( parts ) != 7 )
        continue;

      id    = chomp( parts[0] );
      name  = chomp( parts[ ( max_index( parts ) - 1 ) ] );
      image = chomp( parts[1] );

      if( max_index( parts ) == 6 ) {
        ports = "N/A";
        state = chomp( chomp( parts[ ( max_index( parts ) - 2 ) ] ) );
      } else {
        ports = chomp( chomp( parts[ ( max_index( parts ) - 2 ) ] ) );
        state = chomp( chomp( parts[ ( max_index( parts ) - 3 ) ] ) );
      }

      if( ! id || ! name || ! image )
        continue;

      set_kb_item( name:"docker/lsc/container/" + id + "/id",    value:id );
      set_kb_item( name:"docker/lsc/container/" + id + "/name",  value:name );
      set_kb_item( name:"docker/lsc/container/" + id + "/image", value:image );
      set_kb_item( name:"docker/lsc/container/" + id + "/ports", value:ports );
      set_kb_item( name:"docker/lsc/container/" + id + "/state", value:state );

      if( state !~ "^Up " )
        continue;

      cdata += "Name:  " + name  + '\n' +
               "ID:    " + id    + '\n' +
               "Image  " + image + '\n';

      os_array = get_container_os( container_id:id, soc:soc );

      if( os_array["OS"] )
        cdata += "OS     " + os_array["OS"] + '\n';
      else
        cdata += 'OS:    Unknown\n';

      if( os_array["OS-CPE"] )
        cdata += "CPE:   " + os_array["OS-CPE"] + '\n';

      cdata += "Ports: " + ports + '\n';

      cdata += '\n';
    }
  }
} else if( not_running_or_no_perms ) {

  # nb: If we don't have the permission to call "docker info" we can at least try to grab the
  # version from the dockerd binary. The binary was located in /usr/bin/dockerd on all tested
  # platforms so we're just calling the binary directly for now.
  buf = ssh_cmd( socket:soc, cmd:"dockerd --version" );
  if( buf && "Docker version " >< buf ) {

    # Docker version 1.13.1, build 0be3e21/1.13.1
    # Docker version 18.09.0, build b3d3b90
    # Docker version 19.03.8, build afacb8b7f0
    v = eregmatch( pattern:"Docker version ([0-9.]+)", string:buf );
  }
}

close( soc );

cpe = "cpe:/a:docker:docker";
version = "unknown";

if( ! isnull( v[1] ) ) {
  version = v[1];
  cpe += ":" + version;
  replace_kb_item( name:"docker/version", value:version );
}

register_product( cpe:cpe, location:"ssh", port:0, service:"ssh-login" );

report = build_detection_report( app:"Docker", version:version, install:"ssh", cpe:cpe, concluded:v[0], extra:extra );

if( cdata ) {
  set_kb_item( name:"docker/container/present", value:TRUE );
  report += '\nThe following containers where detected running on the remote host:\n\n' + cdata;
}

log_message( port:0, data:report );

exit( 0 );