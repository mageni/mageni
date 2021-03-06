###############################################################################
# OpenVAS Vulnerability Test
#
# xtux server detection
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11016");
  script_version("2020-08-27T11:07:45+0000");
  script_tag(name:"last_modification", value:"2020-08-27 11:59:41 +0000 (Thu, 27 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("xtux server detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/xtux", 8390);

  script_xref(name:"URL", value:"https://sourceforge.net/p/xtux/bugs/9/#249b");

  script_tag(name:"solution", value:"Disable it, or at least firewall it.");

  script_tag(name:"summary", value:"The xtux server might be running on this port. If somebody connects to
  it and sends it garbage data, it may loop and overload your CPU.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

# nb: xtux server will start looping and eat CPU if it receives bad input.
# Writing a nice plugin is useless, as xtux is killed by find_service!

include("misc_func.inc");

port = get_port_for_service( default:8390, proto:"xtux" );

# For the case if "unscanned_closed = no" is used.
# Also used as the check below only checks if it
# is possible to open a socket to this port.
if( ! verify_service( port:port, proto:"xtux" ) &&
    ! service_is_unknown( port:port ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( soc ) {
  log_message( port:port );
  close( soc );
  exit( 0 );
}

exit( 0 );
