###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_cookie_secure_flag_info_disc_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# SSL/TLS: Missing `secure` Cookie Attribute
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.902661");
  script_version("$Revision: 11374 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-01 17:10:53 +0530 (Thu, 01 Mar 2012)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name('SSL/TLS: Missing `secure` Cookie Attribute');
  script_copyright("Copyright (C) 2012 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  # nb: Don't add a dependency to http_version.nasl to allow a minimal SSL/TLS check configuration
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/SecureFlag");
  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc2965.txt");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OWASP-SM-002)");

  script_tag(name:"summary", value:"The host is running a server with SSL/TLS and is prone to information
  disclosure vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to cookie is not using 'secure' attribute, which
  allows cookie to be passed to the server by the client over non-secure channels (http) and allows attacker
  to conduct session hijacking attacks.");

  script_tag(name:"affected", value:"Server with SSL/TLS.");

  script_tag(name:"solution", value:"Set the 'secure' attribute for any cookies that are sent over a SSL/TLS connection.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

## Exit on non-ssl port
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

res = http_get_cache( item: "/", port:port );

if( res && "Set-Cookie:" >< res ) {

  cookies = egrep( string:res, pattern:"Set-Cookie:.*" );

  if( cookies ) {

    cookiesList = split( cookies, sep:'\n', keep:FALSE );
    vuln = FALSE;

    foreach cookie( cookiesList ) {

      if( cookie !~ ";[ ]?[S|s]ecure?[^a-zA-Z0-9_-]?" ) {
        # Clean-up cookies from dynamic data so we don't report differences on the delta report
        pattern = "(Set-Cookie:.*=)([a-zA-Z0-9]+)(;.*)";
        if( eregmatch( pattern:pattern, string:cookie ) ) {
          cookie_replace = ereg_replace( string:cookie, pattern:pattern, replace:"\1***replaced***\3" );
          cookie = substr(cookie_replace, 0, 50);
        }
        vuln = TRUE;
        vulnCookies += cookie + '\n';
      }
    }

    if( vuln ) {
      report = 'The cookies:\n\n' + vulnCookies + '\nare missing the "secure" attribute.';
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );