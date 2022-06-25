###############################################################################
# OpenVAS Vulnerability Test
# $Id: osticket_backdoored.nasl 10829 2018-08-08 09:06:21Z cfischer $
#
# osTicket Backdoored
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

# From: Guy Pearce <dt_student@hotmail.com>
# Date: 21.6.2004 08:01
# Subject: Multiple osTicket exploits!

# This script detects those osTicket systems that were backdoored,
# not the vulnerability

CPE = "cpe:/a:osticket:osticket";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12649");
  script_version("$Revision: 10829 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 11:06:21 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("osTicket Backdoored");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_tag(name:"solution", value:"1) Remove any PHP files from the /attachments/ directory.

  2) Place an index.html file there to prevent directory listing of that directory.

  3) Upgrade osTicket to the latest version.");

  script_tag(name:"summary", value:"There is a vulnerability in the current version of osTicket
  that allows an attacker to upload an PHP script, and then access it causing it to execute.

  This script tries to detect infected servers.");

  script_tag(name:"impact", value:"This attack is being actively exploited by attackers to take over
  servers.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

req = http_get(item:dir +  "/attachments/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( isnull( res ) || "[DIR]" >!< res ) exit( 0 );

# There is a directory there, so directory listing worked
v = eregmatch( pattern:'<A HREF="([^"]+.php)">', string:res );
if( isnull( v ) ) exit( 0 );

url = dir + "/attachments/" + v[1];
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( isnull( res ) ) exit( 0 );

if( "PHP Shell" >< res || "<input type = 'text' name = 'cmd' value = '' size = '75'>" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );