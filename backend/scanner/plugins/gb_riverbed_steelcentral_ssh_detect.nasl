###############################################################################
# OpenVAS Vulnerability Test
#
# Riverbed SteelCentral Detection (SSH Banner)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105788");
  script_version("2019-05-21T13:46:00+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 13:46:00 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2016-06-30 13:36:05 +0200 (Thu, 30 Jun 2016)");
  script_name("Riverbed SteelCentral Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/riverbed/steelcentral/detected");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the SSH banner.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

source = "ssh";

port = get_ssh_port( default:22 );
banner = get_kb_item( "SSH/textbanner/" + port );
if( !banner || "Riverbed Cascade" >!< banner )
  exit( 0 );

set_kb_item( name:"riverbed/SteelCentral/detected", value:TRUE );

cpe = 'cpe:/a:riverbed:steelcentral';
vers = 'unknown';

report_app = 'Riverbed SteelCentral';
report_version = 'unknown';

version = eregmatch( pattern:' ([0-9.]+[^ )\r\n]+) \\(release', string:banner );
if( ! isnull( version[1] ) )
{
  vers = version[1];
  report_version = vers;
  cpe += ':' + vers;
  set_kb_item( name:"riverbed/SteelCentral/" + source + "/version", value:vers);
}

rls = eregmatch( pattern:'\\(release ([0-9]+[^) \r\n]+)\\)', string:banner );
if( ! isnull( rls[1] ) )
{
  release = rls[1];
  report_version += ' (' + release + ')';
  set_kb_item( name:"riverbed/SteelCentral/" + source + "/release", value:release );
}

mod = eregmatch( pattern:'Riverbed Cascade ([^ ]+)', string:banner );
if( ! isnull( mod[1] ) )
{
  m = mod[1];
  if( m == "Express" )
    model = 'SCNE-UNKNOWN';
  else if ( m == "Profiler" )
    model = 'SCNP-UNKNOWN';
  else
    model = 'unknown';

  report_app += ' (' + model + ')';

  set_kb_item( name:"riverbed/SteelCentral/" + source + "/model", value:model );
}

if( "(virtual)" >< banner ) set_kb_item( name:"riverbed/SteelCentral/is_vm", value:TRUE );

register_product( cpe:cpe, location:port + "/tcp", port:port, service:"ssh" );
report = build_detection_report( app:report_app, version:report_version, install:port +"/tcp", cpe:cpe, concluded:banner );

log_message( port:port, data:report );

exit( 0 );