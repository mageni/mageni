###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netgear_prosafe_telnet_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# NETGEAR ProSAFE Devices Detection (Telnet)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108310");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-12-07 08:03:31 +0100 (Thu, 07 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETGEAR ProSAFE Devices Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/netgear/prosafe/detected");

  script_tag(name:"summary", value:"This script performs Telnet based detection of NETGEAR ProSAFE devices.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("telnet_func.inc");

port   = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( ! banner )
  exit( 0 );

# nb: It seems to be possible to change the banner.
# The banner also contains only the model name by default so each model needs to be added here.
# Some of the devices are also restricting the amount of connections with a message
# like "Sorry, maximum number of connections reached!"
if( "User:" >< banner && ( "(GSM7224V2)" >< banner || "(GSM7224)" >< banner ) ) {

  model      = "unknown";
  fw_version = "unknown";
  fw_build   = "unknown";

  mod = eregmatch( pattern:"\(([0-9a-zA-Z\\-]+)\)", string:banner, icase:TRUE );
  if( mod[1] ) {
    model = mod[1];
    set_kb_item( name:"netgear/prosafe/telnet/" + port + "/concluded", value:mod[0] );
  }

  set_kb_item( name:"netgear/prosafe/telnet/" + port + "/model", value:model );
  set_kb_item( name:"netgear/prosafe/telnet/" + port + "/fw_version", value:fw_version );
  set_kb_item( name:"netgear/prosafe/telnet/" + port + "/fw_build", value:fw_build );
  set_kb_item( name:"netgear/prosafe/telnet/detected", value:TRUE );
  set_kb_item( name:"netgear/prosafe/telnet/port", value:port );
  set_kb_item( name:"netgear/prosafe/detected", value:TRUE );
}

exit( 0 );