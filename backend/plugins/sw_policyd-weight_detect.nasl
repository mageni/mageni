###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_policyd-weight_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# poliycd-weight Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111037");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-09-12 10:00:00 +0200 (Sat, 12 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("poliycd-weight Server Detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_dependencies("find_service_3digits.nasl");
  script_require_ports("Services/unknown", 12525);

  script_tag(name:"summary", value:"The script checks the presence of a policyd-weight server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

port = get_unknown_port( default:12525 );

host = get_host_name();

soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = "helo_name=" + host + '\r\n' +
      "sender=openvas@" + host + '\r\n' +
      "client_address=" + get_host_ip() + '\r\n' +
      "request=smtpd_access_policy" + '\r\n\r\n';

send( socket:soc, data:req );
buf = recv( socket:soc, length:256 );
close( soc );

if( concluded = egrep( string:buf, pattern:"action=(ACTION|DUNNO|550|450|PREPEND)(.*)" ) ) {

  install = port + "/tcp";
  register_service( port:port, proto:"policyd-weight" );
  set_kb_item( name:"policyd-weight/installed", value:TRUE );

  ## CPE is currently not registered
  cpe = 'cpe:/a:policyd-weight:policyd-weight';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"policyd-weight server",
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );
