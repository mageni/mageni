# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117414");
  script_version("2021-05-11T13:41:53+0000");
  script_cve_id("CVE-2013-3587");
  script_tag(name:"last_modification", value:"2021-05-12 10:16:15 +0000 (Wed, 12 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-11 12:30:48 +0000 (Tue, 11 May 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("SSL/TLS: BREACH attack against HTTP compression");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_tls_version_get.nasl", "find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"http://breachattack.com/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/987798");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2013/08/07/1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=995168");
  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/HTTP_compression");

  script_tag(name:"summary", value:"SSL/TLS connections are vulnerable to the 'BREACH' (Browser
  Reconnaissance & Exfiltration via Adaptive Compression of Hypertext) attack.");

  script_tag(name:"vuldetect", value:"Checks if the remote web server has HTTP compression enabled.

  Note: Even with HTTP compression enabled the web application hosted on the web server might not
  be vulnerable. The low Quality of Detection (QoD) of this VT reflects this fact.");

  script_tag(name:"insight", value:"Angelo Prado, Neal Harris and Yoel Gluck reported that SSL/TLS
  attacks are still viable via a 'BREACH' (Browser Reconnaissance & Exfiltration via Adaptive
  Compression of Hypertext) attack, which they describe as:

  While CRIME was mitigated by disabling TLS/SPDY compression (and by modifying gzip to allow for
  explicit separation of compression contexts in SPDY), BREACH attacks HTTP responses. These are
  compressed using the common HTTP compression, which is much more common than TLS-level
  compression. This allows essentially the same attack demonstrated by Duong and Rizzo, but without
  relying on TLS-level compression (as they anticipated).

  It is important to note that the attack is agnostic to the version of TLS/SSL, and does not
  require TLS-layer compression. Additionally, the attack works against any cipher suite. Against a
  stream cipher, the attack is simpler: The difference in sizes across response bodies is much more
  granular in this case. If a block cipher is used, additional work must be done to align the output
  to the cipher text blocks.");

  script_tag(name:"impact", value:"The flaw makes it easier for man-in-the-middle attackers to
  obtain plaintext secret values.");

  script_tag(name:"affected", value:"BREACH is a category of vulnerabilities and not a specific
  instance affecting a specific piece of software. To be vulnerable, a web application must:

  - Be served from a server that uses HTTP-level compression

  - Reflect user-input in HTTP response bodies

  - Reflect a secret (such as a CSRF token) in HTTP response bodies");

  script_tag(name:"solution", value:"The following mitigation possibilities are available:

  1. Disabling HTTP compression

  2. Separating secrets from user input

  3. Randomizing secrets per request

  4. Masking secrets (effectively randomizing by XORing with a random secret per request)

  5. Protecting vulnerable pages with CSRF

  6. Length hiding (by adding random number of bytes to the responses)

  7. Rate-limiting the requests

  Note: The mitigations are ordered by effectiveness (not by their practicality - as this may differ
  from one application to another).");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("ssl_funcs.inc");
include("misc_func.inc");

port = http_get_port( default:443 );

# Exit on non-ssl http port (reporting the flaw doesn't make any sense in this case).
if( ! tls_ssl_is_enabled( port:port ) )
  exit( 0 );

# We're just checking these two for now.
accept_encoding = "gzip, deflate";

# Examples sent by a server having HTTP compression enabled:
# Accept-Encoding: gzip, deflate
# Content-Encoding: gzip
# Accept-Encoding: gzip, deflate, identity
# Accept-Encoding: gzip,chunked
check_pattern = '^([Aa]ccept|[Cc]ontent)-[Ee]ncoding\\s*:[^\r\n]*(gzip|deflate)';

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = dir + "/";
  req = http_get_req( port:port, url:url, accept_encoding:accept_encoding );
  res = http_keepalive_send_recv( port:port, data:req, headersonly:TRUE );
  if( ! res || res !~ "^HTTP/1\.[01] [0-9]{3}" )
    continue;

  if( found = egrep( string:res, pattern:check_pattern, icase:FALSE ) ) {

    info["URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    info["HTTP headers"] = found;

    found   = chomp( found );
    found   = str_replace( string:found, find:'\r\n', replace:"<newline>" );
    report  = 'Based on the following information it was determined that the remote web server has HTTP compression enabled:\n\n';
    report += text_format_table( array:info );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );