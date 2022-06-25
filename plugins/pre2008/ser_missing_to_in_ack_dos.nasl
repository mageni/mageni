###############################################################################
# OpenVAS Vulnerability Test
# $Id: ser_missing_to_in_ack_dos.nasl 13734 2019-02-18 11:03:47Z cfischer $
#
# SIP Express Router Missing To in ACK DoS
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
  script_oid("1.3.6.1.4.1.25623.1.0.11964");
  script_version("$Revision: 13734 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 12:03:47 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(6904);
  script_cve_id("CVE-2003-1108");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("SIP Express Router Missing To in ACK DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
  script_family("Denial of Service");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/banner/available");

  script_xref(name:"URL", value:"http://www.cert.org/advisories/CA-2003-06.html");

  script_tag(name:"solution", value:"Upgrade to version 0.8.10.");

  script_tag(name:"summary", value:"The remote host is a SIP Express Router (SER).

  The SER product has been found to contain a vulnerability where ACKs
  requests without a To header, when SER has been enabled to use the SL module,
  can be used to crash the product.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("sip.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos['port'];
proto = infos['proto'];

banner = sip_get_banner( port:port, proto:proto );
if ( ! banner ) exit( 0 );
# Sample: Sip EXpress router (0.8.12 (i386/linux))

if( egrep( pattern:"Sip EXpress router \((0\.[0-7]\.|0\.8\.[0-9]) ", string:banner ) ) {
  security_message( port:port, protocol:proto );
  exit( 0 );
}

exit( 99 );