###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ngips_version.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Cisco NGIPS Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140154");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-08 15:08:04 +0100 (Wed, 08 Feb 2017)");
  script_name("Cisco NGIPS Detection");

  script_tag(name:"summary", value:"This script performs SSH based detection of Cisco NGIPS");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("cisco/ngips/uname");
  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! uname = get_kb_item( "cisco/ngips/uname" ) ) exit( 0 );
if( "Cisco NGIPS" >!< uname ) exit( 0 );

set_kb_item( name:"cisco/ngips/detected", value:TRUE );

version = "unknown";
rep_version = "unknown";

cpe = 'cpe:/a:cisco:firepower_ngips';

v = eregmatch( pattern:"Cisco NGIPS.*v([0-9.]+) \(build ([0-9]+)\)", string:uname );

if( ! isnull( v[1] ) )
{
  version = v[1];
  cpe += ':' + version;
  set_kb_item( name:"cisco/ngips/version", value:version );
  rep_version = version;
}

if( ! isnull( v[2] ) )
{
  set_kb_item( name:"cisco/ngips/build", value:v[2] );
  rep_version += ' Build ' + v[2];
}

register_product( cpe:cpe, location:"ssh" );

soc = ssh_login_or_reuse_connection();
if( soc )
{
  show_model = ssh_cmd( socket:soc, cmd:'show model', nosh:TRUE, pty:TRUE, clear_buffer:TRUE );
  set_kb_item(name:"cisco/ngips/show_model", value:show_model);
  close( soc );
}


if( "for VMware" >< uname )
  set_kb_item( name:"cisco/ngips/is_vm", value:TRUE );

report = build_detection_report( app:"Cisco NGIPS", version:rep_version, install:"ssh",  cpe:cpe, concluded:v[0] );

log_message( port:0, data:report );

exit( 0 );

