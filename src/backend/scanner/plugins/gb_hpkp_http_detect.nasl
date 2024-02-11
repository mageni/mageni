# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108245");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name("SSL/TLS: HTTP Public Key Pinning (HPKP) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  # nb: Don't add a dependency to e.g. webmirror.nasl or DDI_Directory_Scanner.nasl
  # to allow a minimal SSL/TLS check configuration.
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/");
  script_xref(name:"URL", value:"https://owasp.org/www-project-secure-headers/#public-key-pinning-extension-for-http-hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"Checks if the remote web server has HTTP Public Key Pinning
  (HPKP) enabled.

  Note: Most major browsers have dropped / deprecated support for this header in 2020.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443, ignore_cgi_disabled:TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 )
  exit( 0 );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

if( ! pkp = egrep( pattern:"^Public-Key-Pins\s*:", string:banner, icase:TRUE ) ) { # Public-Key-Pins-Report-Only is used for testing only
  # The 304 status code has a special meaning and shouldn't contain any additional headers -> https://tools.ietf.org/html/rfc2616#section-10.3.5
  # e.g. mod_headers from Apache won't add additional headers on this code so don't complain about a missing header.
  # nb: There might be still some web servers sending the headers on a 304 status code so we're still reporting it below if there was a header included.
  if( banner !~ "^HTTP/1\.[01] 304" ) {
    set_kb_item( name:"hpkp/missing", value:TRUE );
    set_kb_item( name:"hpkp/missing/port", value:port );
  }
  exit( 0 );
}

pkp = chomp( pkp );
pkp_lo = tolower( pkp );

# max-age is required: https://tools.ietf.org/html/rfc7469#page-19
# Assume a missing HPKP if its not specified
if( "max-age=" >!< pkp_lo ) {
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/max_age/missing/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

# Assuming missing support if value is set to zero
if( "max-age=0" >< pkp_lo ) {
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/max_age/zero/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

# Assuming missing support if no pin-sha256= is included
# Currently only pin-sha256 is supported / defined but this might change in the future
if( "pin-sha256=" >!< pkp_lo ) {
  set_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/pin/missing/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

set_kb_item( name:"hpkp/available", value:TRUE );
set_kb_item( name:"hpkp/available/port", value:port );
set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );

if( "includesubdomains" >!< pkp_lo ) {
  set_kb_item( name:"hpkp/includeSubDomains/missing", value:TRUE );
  set_kb_item( name:"hpkp/includeSubDomains/missing/port", value:port );
}

ma = eregmatch( pattern:"max-age=([0-9]+)", string:pkp, icase:TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name:"hpkp/max_age/" + port, value:ma[1] );

log_message( port:port, data:'The remote web server is sending the "HTTP Public Key Pinning" header.\n\nHPKP-Header:\n\n' + pkp );

exit( 0 );
