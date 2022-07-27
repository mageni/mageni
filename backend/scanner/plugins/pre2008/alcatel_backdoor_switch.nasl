###############################################################################
# OpenVAS Vulnerability Test
#
# Alcatel OmniSwitch 7700/7800 switches backdoor
#
# Authors:
# deepquest <deepquest@code511.com>
# Modifications by rd:
# -  added ref: http://www.cert.org/advisories/CA-2002-32.html
# -  removed leftovers in the code (send(raw_string(0, 0))
# -  added the use of telnet_init()
# -  replaced open_sock_udp by open_sock_tcp()
# -  added script id
# -  attributed copyright properly to deepquest
# -  merged some ideas from Georges Dagousset <georges.dagousset@alert4web.com>
#    who wrote a duplicate of this script
#
# Copyright:
# Copyright (C) 2005 deepquest
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
  script_oid("1.3.6.1.4.1.25623.1.0.11170");
  script_version("2020-08-28T06:20:13+0000");
  script_tag(name:"last_modification", value:"2020-08-28 09:48:35 +0000 (Fri, 28 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6220);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2002-1272");
  script_name("Alcatel OmniSwitch 7700/7800 switches backdoor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 deepquest");
  script_family("Malware");
  script_dependencies("find_service.nasl", "telnet.nasl");
  script_require_ports(6778);

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2002-32.html");

  script_tag(name:"solution", value:"Block access to port 6778/TCP or update to
  AOS 5.1.1.R02 or AOS 5.1.1.R03.");

  script_tag(name:"summary", value:"The remote host seems to be a backdoored
  Alcatel OmniSwitch 7700/7800.");

  script_tag(name:"impact", value:"An attacker can gain full access to any device
  running AOS version 5.1.1, which can result in, but is not limited to,
  unauthorized access, unauthorized monitoring, information leakage,
  or denial of service.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = 6778;

# For the case if "unscanned_closed = no" is used.
# Also used as the check below only checks if it
# is possible to open a socket to this port.
if( ! verify_service( port:port, proto:"telnet" ) )
  exit( 0 );

soc = open_sock_tcp( port );
if( ! soc )
  exit( 0 );

data = telnet_get_banner( port:port );
telnet_close_socket( socket:soc, data:data );

if( data ) {
  security_message( port:port, data:'Banner:\n' + data );
  exit( 0 );
}

exit( 99 );
