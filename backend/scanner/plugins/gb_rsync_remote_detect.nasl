# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108731");
  script_version("2020-03-24T14:04:53+0000");
  script_tag(name:"last_modification", value:"2020-03-26 10:47:35 +0000 (Thu, 26 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-24 13:59:25 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("rsync Detection (Remote)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/rsync", 873);

  script_tag(name:"summary", value:"A service supporting the rsync protocol is running at this host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("rsync_func.inc");
include("misc_func.inc");

port = rsync_get_port( default:873 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

res = recv_line( socket:soc, length:1024 );
# nb: The same pattern is also checked in find_service1.nasl and find_service2.nasl. Please update those
# when updating the pattern here.
if( ! res || ( res !~ "^@RSYNCD: [0-9.]+" && res !~ "^You are not welcome to use rsync from " && res !~ "^rsync: (link_stat |error |.+unknown option)" && res !~ "rsync error: (syntax or usage error|some files/attrs were not transferred) " ) ) {
  close( soc );
  exit( 0 );
}

set_kb_item( name:"rsync/detected", value:TRUE );
set_kb_item( name:"rsync/remote/detected", value:TRUE );
register_service( port:port, ipproto:"tcp", proto:"rsync", message:"A service supporting the rsync protocol is running at this port." );

protocol = eregmatch( string:res, pattern:"^@RSYNCD: ([0-9.]+)", icase:FALSE );
if( protocol[1] ) {
  report = "Detected RSYNCD protocol version: " + protocol[1];
  set_kb_item( name:"rsync/protocol_banner/" + port, value:protocol[0] );
  set_kb_item( name:"rsync/protocol_banner/available", value:TRUE );
}

if( res =~ "^You are not welcome to use rsync from " ) {
  if( report )
    report += '\n\n';
  report += "The rsync service is not allowing connections from this host.";
}

motd = "";

# Grab the MOTD
while( TRUE ) {
  buf = recv_line( socket:soc, length:8096 );
  if( ! buf || strstr( buf, '@ERROR' ) )
    break;
  motd += buf;
}

close( soc );

if( motd =~ "rsync: (link_stat |error |.+unknown option)" || "rsync error: " >< motd ||
    res =~ "rsync: (link_stat |error |.+unknown option)" || "rsync error: " >< res ) {
  motd_has_error = TRUE;
  if( report )
    report += '\n\n';
  if( "@RSYNCD:" >!< res )
    motd = res + motd;

  report += 'The rsync service is in a non-working state and reports the following error:\n\n' + chomp( motd );
}

if( motd && ! motd_has_error ) {
  motd = chomp( motd );
  if( report )
    report += '\n\n';
  report += 'Message of the Day reported by the service:\n\n' + motd;
  set_kb_item( name:"rsync/motd/" + port, value:motd );
  set_kb_item( name:"rsync/motd/available", value:TRUE );
}

log_message( port:port, data:report );

exit( 0 );
