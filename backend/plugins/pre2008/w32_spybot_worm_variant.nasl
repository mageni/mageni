###############################################################################
# OpenVAS Vulnerability Test
# $Id: w32_spybot_worm_variant.nasl 9324 2018-04-05 09:28:03Z cfischer $
#
# w32.spybot.fcd worm infection
#
# Authors:
# Jorge E Rodriguez <KPMG>
# - check the system for infected w32.spybot.fbg
# - script id
# - cve id
#
# Copyright:
# Copyright (C) 2004 jorge rodriguez
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.15520");
  script_version("$Revision: 9324 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 11:28:03 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("w32.spybot.fcd worm infection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 jorge rodriguez");
  script_family("Malware");
  script_dependencies("find_service1.nasl", "os_detection.nasl");
  script_require_ports(113);
  script_exclude_keys('fake_identd/113');
  script_mandatory_keys("Host/runs_windows");

  script_xref(name:"URL", value:"http://securityresponse.symantec.com/avcenter/venc/data/w32.spybot.fcd.html");

  script_tag(name:"summary", value:"The remote system is infected with a variant of the worm w32.spybot.fcd.");

  script_tag(name:"impact", value:"Infected systems will scan systems that are vulnerable in the same subnet
  in order to attempt to spread.

  This worm also tries to do DDoS against targets in the Internet.");

  script_tag(name:"solution", value:"Ensure all MS patches are applied as well as the latest AV
  definitions.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include('misc_func.inc');
include('host_details.inc');

if( get_kb_item( 'fake_identd/113' ) ) exit( 0 );

port = 113;
if( ! get_port_state( port ) ) exit( 0 );
soc = open_sock_tcp( port );
if( ! soc ) exit( 0 );

req = string("GET\r\n");
send( socket:soc, data:req );
r = recv( socket:soc, length:16000 );
close( soc );

if( " : USERID : UNIX :" >< r ) {

  if( "GET : USERID : UNIX :" >< r ) exit( 99 );

  security_message( port:port );

  if( service_is_unknown( port:port ) )
    register_service( port:port, proto:'fake-identd' );

  set_kb_item( name:'fake_identd/113', value:TRUE );
  exit( 0 );
}

exit( 99 );