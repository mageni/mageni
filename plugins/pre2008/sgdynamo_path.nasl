###############################################################################
# OpenVAS Vulnerability Test
# $Id: sgdynamo_path.nasl 11996 2018-10-19 19:08:41Z cfischer $
#
# Sgdynamo 'sgdynamo.exe' Physical Path Disclosure Vulnerability
#
# Authors:
# Scott Shebby (12/2003)
#
# Copyright:
# Copyright (C) 2003 Scott Shebby
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
###############################################################################

# Ref:
# From: "Ruso, Anthony" <aruso@positron.qc.ca>
# To: Penetration Testers <PEN-TEST@SECURITYFOCUS.COM>
# Subject: Sgdynamo.exe Script -- Path Disclosure
# Date: Wed, 16 May 2001 11:55:32 -0400

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11954");
  script_version("$Revision: 11996 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 21:08:41 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("Sgdynamo 'sgdynamo.exe' Physical Path Disclosure Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 Scott Shebby");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Host/runs_windows");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The CGI 'sgdynamo.exe' can be tricked into giving the physical path to the
  remote web root.");

  script_tag(name:"impact", value:"This information may be useful to an attacker who can use it to make better
  attacks against the remote server.");

  script_tag(name:"qod", value:"50"); # No extra check, prone to false positives and doesn't match existing qod_types
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/sgdynamo.exe?HTNAME=sgdynamo.exe";

  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  if( !res || res !~ "^HTTP/1\.[01] 200" ) continue;

  path = egrep( pattern:"[aA-zZ]:\\.*sgdynamo\.exe", string:res );
  if( path ) {
    path = ereg_replace( string:path, pattern:".*([aA-zZ]:\\.*sgdynamo\.exe).*", replace:"\1" );
    report = "It is possible to obtain the physical path to the remote website by sending the following request :" +
             egrep( pattern:"^GET /", string:req ) +
             "We determined that the remote web path is : '" + path + "'";
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );