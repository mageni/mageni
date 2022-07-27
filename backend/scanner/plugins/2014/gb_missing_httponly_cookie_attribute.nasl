###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_missing_httponly_cookie_attribute.nasl 5270 2017-02-10 17:18:49Z cfi $
#
# Missing `httpOnly` Cookie Attribute
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2014 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105925");
  script_version("$Revision: 5270 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-10 18:18:49 +0100 (Fri, 10 Feb 2017) $");
  script_tag(name:"creation_date", value:"2014-09-01 16:00:00 +0100 (Mon, 01 Sep 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name('Missing `httpOnly` Cookie Attribute');
  script_copyright("Copyright (c) 2014 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/HttpOnly");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Testing_for_cookies_attributes_(OTG-SESS-002)");

  script_tag(name:"summary", value:"The application is missing the 'httpOnly' cookie attribute");

  script_tag(name:"vuldetect", value:"Check all cookies sent by the application for a missing 'httpOnly' attribute");

  script_tag(name:"insight", value:"The flaw is due to a cookie is not using the 'httpOnly' attribute. This
  allows a cookie to be accessed by JavaScript which could lead to session hijacking attacks.");

  script_tag(name:"affected", value:"Application with session handling in cookies.");

  script_tag(name:"solution", value:"Set the 'httpOnly' attribute for any session cookie.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

buf = http_get_cache( item:"/", port:port );

if( buf && "Set-Cookie:" >< buf ) {

  cookies = egrep( string:buf, pattern:"Set-Cookie:.*" );

  if( cookies ) {

    cookiesList = split( cookies, sep:'\n', keep:FALSE );
    vuln = FALSE;

    foreach cookie( cookiesList ) {

      if( cookie !~ ";[ ]?[H|h]ttp[O|o]nly?[^a-zA-Z0-9_-]?" ) {
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
      report = 'The cookies:\n\n' + vulnCookies + '\nare missing the "httpOnly" attribute.';
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );