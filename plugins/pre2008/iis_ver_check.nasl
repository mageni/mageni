###############################################################################
# OpenVAS Vulnerability Test
# $Id: iis_ver_check.nasl 4703 2016-12-07 13:45:38Z cfi $
#
# IIS Service Pack - 404
#
# Authors:
# SensePost
# Modification by David Maciejak
# <david dot maciejak at kyxar dot fr>
# based on 404print.c from Digital Defense
#
# Copyright:
# Copyright (C) 2003 SensePost & Copyright (C) 2004 David Maciejak
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11874");
  script_version("$Revision: 4703 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-07 14:45:38 +0100 (Wed, 07 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IIS Service Pack - 404");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2003 SensePost & Copyright (C) 2004 David Maciejak");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_tag(name:"solution", value:"The Patch level (Service Pack) of the remote IIS server appears to be lower
  than the current IIS service pack level. As each service pack typically
  contains many security patches, the server may be at risk.

  Caveat: This test makes assumptions of the remote patch level based on static
  return values (Content-Length) within the IIS Servers 404 error message.
  As such, the test can not be totally reliable and should be manually confirmed.");

  script_tag(name:"summary", value:"Ensure that the server is running the latest stable Service Pack");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the detection NVT

sig = get_http_banner( port:port );
if( sig && "IIS" >!< sig ) exit( 0 );

req = http_get( item:"/openvas" + rand(), port:port );
r  = http_keepalive_send_recv( data:req, port:port );
if( r == NULL ) exit( 0 );
if( ! ereg( pattern:"^HTTP.* 404 .*", string:r ) ) exit( 0 );

v4 = egrep( pattern:"^Server:.*Microsoft-IIS/4\.0", string:r );
v5 = egrep( pattern:"^Server:.*Microsoft-IIS/5\.0", string:r );
v51 = egrep( pattern:"^Server:.*Microsoft-IIS/5\.1", string:r );
v6 = egrep( pattern:"^Server:.*Microsoft-IIS/6\.0", string:r );

cltmp = eregmatch( pattern:".*Content-Length: ([0-9]+).*", string:r );
if( isnull( cltmp ) ) exit( 0 );
cl = int( cltmp[1] );

ver = string( "The remote IIS server *seems* to be " );

#if( v4 ) {
#  if( 102 == cl ) ver += string( "Microsoft IIS 4 - Sp0\n" );
#  if( 451 == cl ) ver += string( "Microsoft IIS 4 - SP6\n" );
#  if( 461 == cl ) ver += string( "Microsoft IIS 4 - SP3\n" );
#}

if( v5 ) {
#??
#  if( 111 == cl ) ver += string( "Microsoft IIS 5 - SP4\n" );
  if( 3243 == cl ) ver += string( "Microsoft IIS 5 - SP0 or SP1\n" );
  if( 2352 == cl ) ver += string( "Microsoft IIS 5 - SP2 or SRP1\n" );
  if( 4040 == cl ) ver += string( "Microsoft IIS 5 - SP3 or SP4\n" );
}

if( v51 ) {
  if( 1330 == cl ) ver += string( "Microsoft IIS 5.1 - SP2\n" );
  if( 4040 == cl ) ver += string( "Microsoft IIS 5.1 - SP0\n" );
}

if( v6 ) {
  if( 2166 == cl ) ver += string( "Microsoft IIS 6.0 - SP0\n" );
  if( 1635 == cl ) ver += string( "Microsoft IIS 6.0 - w2k3 build 3790\n" );
}

if( ver !=  "The remote IIS server *seems* to be " ) {
  security_message( port:port, data:ver );
  exit ( 0 );
}

exit( 99 );
