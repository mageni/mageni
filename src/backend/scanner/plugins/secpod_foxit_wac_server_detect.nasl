###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_foxit_wac_server_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# Foxit WAC Server Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900923");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Foxit WAC Server Version Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "ssh_detect.nasl");
  script_require_ports("Services/ssh", 22, "Services/telnet", 23);
  script_mandatory_keys("ssh_or_telnet/foxit/wac-server/detected");

  script_tag(name:"summary", value:"This script finds the version of Foxit WAC Server and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");
include("telnet_func.inc");

function set_detection( port, banner, service ) {

  local_var port, banner, service;
  local_var cpe;

  set_kb_item( name:"Foxit-WAC-Server/installed", value:TRUE );
  install = port + "/tcp";
  version = "unknown";

  vers = eregmatch( pattern:"(Foxit-WAC-Server-|WAC Server )(([0-9.]+).?(([a-zA-Z]+[ 0-9]+))?)", string:banner );
  if( ! isnull( vers[2] ) ) {
    version = ereg_replace( pattern:" ", string:vers[2], replace:"." );
    version = ereg_replace( pattern:"\.Build", string:version, replace:"" );
  }

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:wac_server:" );
  if( ! cpe )
    cpe = "cpe:/a:foxitsoftware:wac_server";

  register_product( cpe:cpe, location:install, port:port, service:service );

  log_message( data:build_detection_report( app:"Foxit WAC Server",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0] ),
                                            port:port );
}

telnetPorts = telnet_get_ports();

foreach port( telnetPorts ) {
  banner = get_telnet_banner( port:port );
  # Welcome to WAC Server 2.0 Build 3503. (C) Foxit Software, 2002-2003
  if( banner && "WAC" >< banner && "Foxit Software" >< banner )
    set_detection( port:port, banner:banner, service:"telnet" );
}


sshdPort = get_ssh_port( default:22 );
banner   = get_ssh_server_banner( port:sshdPort );

# SSH-1.99-Foxit-WAC-Server-2.0 Build 3503
if( ! banner || "Foxit-WAC-Server" >!< banner )
  exit( 0 );

set_detection( port:sshdPort, banner:banner, service:"ssh" );

exit( 0 );