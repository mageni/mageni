###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netatalk_asip_afp_detect.nasl 12968 2019-01-08 10:15:49Z cfischer $
#
# Netatalk Detection (AppleShare IP / AFP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108527");
  script_version("$Revision: 12968 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 11:15:49 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-08 09:37:20 +0100 (Tue, 08 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Netatalk Detection (AppleShare IP / AFP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("asip-status.nasl");
  script_mandatory_keys("asip_afp/banner/available");

  script_xref(name:"URL", value:"http://netatalk.sourceforge.net/");

  script_tag(name:"summary", value:"This script tries to detect an installed Netatalk service and
  its version on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

port = get_kb_item( "Services/appleshare" );
if( ! port )
  port = 548;

if( ! get_port_state( port ) )
  exit( 0 );

banner = get_kb_item( "asip_afp/" + port + "/banner" );
if( ! banner || banner !~ "^Netatalk" )
  exit( 0 );

version = "unknown";
install = port + "/tcp";

# Netatalk3.0.5
vers = eregmatch( string:banner, pattern:"^Netatalk([0-9.]+)" );
if( vers )
  version = vers[1];

set_kb_item( name:"netatalk/detected", value:TRUE );

register_and_report_cpe( app:"Netatalk", ver:version, concluded:banner, base:"cpe:/a:netatalk:netatalk:", expr:"([0-9.]+)", insloc:install, regPort:port, regService:"appleshare" );

exit( 0 );