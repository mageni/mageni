###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_expect-ct_detect.nasl 14334 2019-03-19 14:35:43Z cfischer $
#
# SSL/TLS: Expect Certificate Transparency (Expect-CT) Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113045");
  script_version("$Revision: 14334 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:35:43 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-07 10:06:44 +0100 (Tue, 07 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SSL/TLS: Expect Certificate Transparency (Expect-CT) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  # nb: Don't add a dependency to http_version.nasl to allow a minimal SSL/TLS check configuration
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This script checks if the HTTP Server has Expect-CT enabled.");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#ect");
  script_xref(name:"URL", value:"https://scotthelme.co.uk/a-new-security-header-expect-ct/");
  script_xref(name:"URL", value:"http://httpwg.org/http-extensions/expect-ct.html");

  exit(0);
}

include( "http_func.inc" );

port = get_http_port( default: 443, ignore_cgi_disabled: TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

banner = get_http_banner( port: port );

# We should not expect a Expect-CT header without a 20x or 30x status code in the response
# e.g. nginx -> https://nginx.org/en/docs/http/ngx_http_headers_module.html#add_header
# 200, 201 (1.3.10), 204, 206, 301, 302, 303, 304, 307 (1.1.16, 1.0.13), or 308 (1.13.0).
#
# 304 has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
# E.g. mod_headers from Apache won't add additional Headers on this code so don't check it here
if( ! banner || banner !~ "^HTTP/1\.[01] (20[0146]|30[12378])" ) exit( 0 );

if( ! ect_hdr = egrep( pattern: "^Expect-CT: ", string: banner, icase: TRUE ) )
{
  set_kb_item( name: "expect-ct/missing", value: TRUE );
  set_kb_item( name: "expect-ct/missing/port", value: port );
  exit( 0 );
}

# max-age is required: http://httpwg.org/http-extensions/expect-ct.html#the-max-age-directive
# Assume a missing Expect-CT if its not specified
if( "max-age=" >!< tolower( ect_hdr ) )
{
  set_kb_item( name: "expect-ct/missing", value: TRUE );
  set_kb_item( name: "expect-ct/missing/port", value: port );
  set_kb_item( name: "expect-ct/max_age/missing/" + port, value: TRUE );
  set_kb_item( name: "expect-ct/" + port + "/banner", value: ect_hdr );
  exit( 0 );
}

# Assuming missing support if value is set to zero
if( "max-age=0" >< tolower( ect_hdr ) )
{
  set_kb_item( name: "expect-ct/missing", value: TRUE );
  set_kb_item( name: "expect-ct/missing/port", value: port );
  set_kb_item( name: "expect-ct/max_age/zero/" + port, value: TRUE );
  set_kb_item( name: "expect-ct/" + port + "/banner", value: ect_hdr );
  exit( 0 );
}

set_kb_item( name: "expect-ct/available", value: TRUE );
set_kb_item( name: "expect-ct/available/port", value: port );
set_kb_item( name: "expect-ct/" + port + "/banner", value: ect_hdr );

if( "enforce" >!< tolower( ect_hdr ) )
{
  set_kb_item( name: "expect-ct/enforce/missing", value: TRUE );
  set_kb_item( name: "expect-ct/enforce/missing/port", value: port );
}

ma = eregmatch( pattern: 'max-age=([0-9]+)', string: ect_hdr, icase: TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name: "expect-ct/max_age/" + port, value:ma[1] );

log_message( port: port, data: 'The remote HTTPS server is sending the "Expect Certificate Transparency" header.ECT-Header:' + ect_hdr );
exit( 0 );
