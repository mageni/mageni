###############################################################################
# OpenVAS Vulnerability Test
#
# eDonkey/eMule detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# This script only checks if ports 4661-4663 are open.
# The protocol is not documented, AFAIK. It was probably 'reverse engineered'
# for mldonkey (do you read OCAML?)
# I sniffed a eDonkey connection, but could not reproduce it.
# There were some information on http://hitech.dk/donkeyprotocol.html
# but I could not use it.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11022");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("eDonkey/eMule detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Peer-To-Peer File Sharing");
  script_dependencies("find_service.nasl");
  script_require_ports(4661, 4662, 4663);

  script_tag(name:"summary", value:"eDonkey might be running on this port. This peer to peer
  software is used to share files.

  1. This may be illegal.

  2. You may have access to confidential files

  3. It may eat too much bandwidth

  * Note: This script only checks if ports 4661-4663 are open

  * and are unknown services.");

  script_tag(name:"solution", value:"Disable it.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("misc_func.inc");

for( port = 4661; port <= 4663; port = port + 1 ) {

  if( get_port_state( port ) ) {
    kb = known_service( port:port );
    if( ! kb || kb == "edonkey" ) {
      soc = open_sock_tcp( port );
      if( soc ) {
        security_message( port:port );
	close( soc );
      }
    }
  }
}

# Looking for the mlDonkey web or telnet interface is useless:
# it only answers on localhost

exit( 0 );