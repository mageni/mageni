###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hsts_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# SSL/TLS: HTTP Strict Transport Security (HSTS) Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105876");
  script_version("$Revision: 10896 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-08-22 13:07:41 +0200 (Mon, 22 Aug 2016)");
  script_name("SSL/TLS: HTTP Strict Transport Security (HSTS) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  # nb: Don't add a dependency to http_version.nasl to allow a minimal SSL/TLS check configuration
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#hsts");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc6797");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"This script checks if the remote HTTPS server has HSTS enabled.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");


port = get_http_port( default:443, ignore_cgi_disabled:TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

banner = get_http_banner( port:port );
# We should not expect a HSTS header without a 20x or 30x status code in the response
# e.g. nginx -> https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header
# 200, 201 (1.3.10), 204, 206, 301, 302, 303, 304, 307 (1.1.16, 1.0.13), or 308 (1.13.0).
#
# 304 has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
# E.g. mod_headers from Apache won't add additional Headers on this code so don't check it here
if( ! banner || banner !~ "^HTTP/1\.[01] (20[0146]|30[12378])" ) exit( 0 );

if( ! sts = egrep( pattern:'^Strict-Transport-Security: ', string:banner, icase:TRUE ) ) { # Header fields are case-insensitive: https://tools.ietf.org/html/rfc7230#section-3.2
  set_kb_item( name:"hsts/missing", value:TRUE );
  set_kb_item( name:"hsts/missing/port", value:port );
  exit( 0 );
}

# max-age is required: https://tools.ietf.org/html/rfc6797#page-16
# Assume a missing HSTS if its not specified
if( "max-age=" >!< tolower( sts ) ) {
  set_kb_item( name:"hsts/missing", value:TRUE );
  set_kb_item( name:"hsts/missing/port", value:port );
  set_kb_item( name:"hsts/max_age/missing/" + port, value:TRUE );
  set_kb_item( name:"hsts/" + port + "/banner", value:sts );
  exit( 0 );
}

# From https://tools.ietf.org/html/rfc6797#page-16:
# A max-age value of zero (i.e., "max-age=0") signals the UA to
# cease regarding the host as a Known HSTS Host
if( "max-age=0" >< tolower( sts ) ) {
  set_kb_item( name:"hsts/missing", value:TRUE );
  set_kb_item( name:"hsts/missing/port", value:port );
  set_kb_item( name:"hsts/max_age/zero/" + port, value:TRUE );
  set_kb_item( name:"hsts/" + port + "/banner", value:sts );
  exit( 0 );
}

set_kb_item( name:"hsts/available", value:TRUE );
set_kb_item( name:"hsts/available/port", value:port );
set_kb_item( name:"hsts/" + port + "/banner", value:sts );

if( "includesubdomains" >!< tolower( sts ) ) {
  set_kb_item( name:"hsts/includeSubDomains/missing", value:TRUE );
  set_kb_item( name:"hsts/includeSubDomains/missing/port", value:port );
}

if( "preload" >!< tolower( sts ) ) {
  set_kb_item( name:"hsts/preload/missing", value:TRUE );
  set_kb_item( name:"hsts/preload/missing/port", value:port );
}

ma = eregmatch( pattern:'max-age=([0-9]+)', string:sts, icase:TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name:"hsts/max_age/" + port, value:ma[1] );

log_message( port:port, data:'The remote HTTPS server is sending the "HTTP Strict-Transport-Security" header. HSTS-Header: ' + sts );
exit( 0 );
