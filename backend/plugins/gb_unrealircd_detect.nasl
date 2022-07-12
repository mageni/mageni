###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unrealircd_detect.nasl 10987 2018-08-15 13:55:40Z cfischer $
#
# UnrealIRCd Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809884");
  script_version("$Revision: 10987 $");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-15 15:55:40 +0200 (Wed, 15 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-02-09 11:54:27 +0530 (Thu, 09 Feb 2017)");
  script_name("UnrealIRCd Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ircd.nasl");
  script_require_ports("Services/irc", 6667);
  script_mandatory_keys("ircd/banner");

  script_tag(name:"summary", value:"Detection of UnrealIRCd Daemon. This script
  sends a request to the server and gets the version from the response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include('host_details.inc');

port = get_kb_item( "Services/irc" );
if( ! port ) port = 6667;

banner = get_kb_item( "irc/banner/" + port );
if( isnull( banner ) ) exit( 0 );
if( "unreal" >!< tolower( banner ) ) exit( 0 );

vers = "unknown";

version = eregmatch( pattern:"[u|U]nreal([0-9.]+[0-9])", string:banner );
if( ! version ) {
  version = eregmatch(pattern:"[u|U]nrealIRCd-([0-9.]+[0-9])", string:banner);
  if( version ) vers = version[1];
} else {
  vers = version[1];
}

set_kb_item( name:"UnrealIRCD/Detected", value:TRUE );

cpe = build_cpe( value:vers, exp:"^([0-9.]+[0-9])", base:"cpe:/a:unrealircd:unrealircd:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:unrealircd:unrealircd";

register_product( cpe:cpe, location:port + "/tcp", port:port );

log_message( data:build_detection_report( app:"UnrealIRCd",
                                          version:vers,
                                          install:port + "/tcp",
                                          cpe:cpe,
                                          concluded:version[0] ),
                                          port:port );

exit(0);
