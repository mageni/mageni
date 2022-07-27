###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_password_disclosure.nasl 11003 2018-08-16 11:08:00Z asteins $
#
# Lantronix Remote Configuration Protocol Password Disclosure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103598");
  script_version("$Revision: 11003 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-08-16 13:08:00 +0200 (Thu, 16 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-10-29 15:28:00 +0100 (Mon, 29 Oct 2012)");
  script_name("Lantronix Remote Configuration Protocol Password Disclosure");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_lantronix_mgm_udp_detect.nasl", "gb_lantronix_mgm_tcp_detect.nasl");
  script_mandatory_keys("lantronix_device/lantronix_remote_conf/password_gathered");

  script_tag(name:"solution", value:"Disable access to UDP port 30718 and/or TCP port 30718.");
  script_tag(name:"summary", value:"Lantronix Devices are prone to a Password Disclosure via the
  remote configuration protocol.

  It was possible to retrieve the setup record from Lantronix devices via the
  config port (30718/udp or 30718/tcp, enabled by default) and to extract the
  Telnet/HTTP password.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

report = 'The device is disclosing the following password(s) (password:port/protocol):\n';

ports = get_kb_list( "Services/udp/lantronix_remote_conf" );
if( ! ports ) ports = make_list( 30718 );
foreach port( ports ) {
  if( ! pass = get_kb_item( "lantronix_device/lantronix_remote_conf_udp/" + port + "/password" ) ) continue;
  report += '\n' + pass + ':' + port + '/udp';
  found = TRUE;
}

ports = get_kb_list( "Services/lantronix_remote_conf" );
if( ! ports ) ports = make_list( 30718 );
foreach port( ports ) {
  if( ! pass = get_kb_item( "lantronix_device/lantronix_remote_conf_tcp/" + port + "/password" ) ) continue;
  report += '\n' + pass + ':' + port + '/tcp';
  found = TRUE;
}

if( found ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );