###############################################################################
# OpenVAS Vulnerability Test
# $Id: find_service3.nasl 13874 2019-02-26 11:51:40Z cfischer $
#
# Service Detection with '<xml/>' Request
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108198");
  script_version("$Revision: 13874 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 12:51:40 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-07-20 14:08:04 +0200 (Thu, 20 Jul 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Service Detection with '<xml/>' Request");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service1.nasl", "find_service2.nasl", "find_service_3digits.nasl");
  script_require_ports("Services/unknown");

  script_tag(name:"summary", value:"This plugin performs service detection.

  This plugin is a complement of find_service.nasl. It sends a '<xml/>'
  request to the remaining unknown services and tries to identify them.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("global_settings.inc");

port = get_kb_item( "Services/unknown" );
if( ! port ) exit( 0 );
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

vt_strings = get_vt_strings();

req = "<" + vt_strings["lowercase"] + "/>";
send( socket:soc, data:req + '\r\n' );
r = recv( socket:soc, length:4096 );
close( soc );

if( ! r ) {
  debug_print( 'service on port ', port, ' does not answer to "' + req + '\\r\\n"' );
  exit( 0 );
}

k = "FindService/tcp/" + port + "/xml";
set_kb_item( name:k, value:r );
if( '\0' >< r )
  set_kb_item( name:k + "Hex", value:hexstr( r ) );

# nb: Zabbix Server is answering with an "OK" here but find_service4.nasl will take the job

if( "oap_response" >< r && "GET_VERSION" >< r ) {
  register_service( port:port, proto:"oap", message:"A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
  log_message( port:port, data:"A OpenVAS Administrator service supporting the OAP protocol seems to be running on this port." );
  exit( 0 );
}

# nb: GMP and OMP services are both still answering with an omp_response only
# so we only can differ between the protocol based on its version detected by
# gb_openvas_manager_detect.nasl.
if( "omp_response" >< r && "GET_VERSION" >< r ) {
  register_service( port:port, proto:"omp_gmp", message:"A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
  log_message( port:port, data:"A OpenVAS / Greenbone Vulnerability Manager supporting the OMP/GMP protocol seems to be running on this port." );
  exit( 0 );
}

# nb: Check_MK Agent, find_service1.nasl should already do the job but sometimes the Agent behaves strange
# and only sends data too late. This is a fallback for such a case.
if( "<<<check_mk>>>" >< r || "<<<uptime>>>" >< r || "<<<services>>>" >< r || "<<<mem>>>" >< r ) {
  # nb: Check_MK Agents seems to not answer to repeated requests in a short amount of time so saving the response here for later processing.
  replace_kb_item( name:"check_mk_agent/banner/" + port, value:r );
  register_service( port:port, proto:"check_mk_agent", message:"A Check_MK Agent seems to be running on this port." );
  log_message( port:port, data:"A Check_MK Agent seems to be running on this port." );
  exit( 0 );
}

########################################################################
#             Unidentified service                                     #
########################################################################

if( ! r0 ) set_unknown_banner( port:port, banner:r );