# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104560");
  script_version("2023-03-01T10:09:26+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:09:26 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-24 08:58:19 +0000 (Fri, 24 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2023-22622");

  # nb: Unreliable because we can only check remotely if the file is accessible but can't determine
  # if the config setting has been done which is already mitigating the flaws.
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("WordPress 'wp-cron.php' Accessible/Enabled (HTTP) - Active Check");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"The remote WordPress instance might have a default setup of
  'wp-cron.php' configured which could have security implications.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following security implications might exist:

  - No CVE: A denial of service (DoS) on high traffic sites caused by WordPress executing
  'wp-cron.php' multiple times a minute using an HTTP request.

  - CVE-2023-22622: WordPress depends on unpredictable client visits to cause wp-cron.php execution
  and the resulting security updates, and the source code describes 'the scenario where a site may
  not receive enough visits to execute scheduled tasks in a timely manner' but neither the
  installation guide nor the security guide mentions this default behavior, or alerts the user about
  security risks on installations with very few visits.");

  script_tag(name:"affected", value:"All WordPress sides having a default setup of 'wp-cron.php'
  configured.");

  script_tag(name:"solution", value:"The following mitigation steps are suggested:

  - Add the following to the 'wp-config.php' file of the instance:

    define('DISABLE_WP_CRON', true);

  - Restrict external access to 'wp-cron.php'

  - Configure and enable a system cron to call 'wp-cron.php' locally via PHP instead

  Please see the references for more information.");

  script_xref(name:"URL", value:"https://patchstack.com/articles/solving-unpredictable-wp-cron-problems-addressing-cve-2023-22622/");
  script_xref(name:"URL", value:"https://medium.com/@thecpanelguy/the-nightmare-that-is-wpcron-php-ae31c1d3ae30");
  script_xref(name:"URL", value:"https://core.trac.wordpress.org/ticket/57159");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-pmh6-cq54-943m");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/wp-cron.php";

res = http_get_cache( port:port, item:url );

# nb: If wp-cron.php is accessible we can see the following:
# - A 200 OK status code
# - A text/html Content-Type
# - An empty body
# We need to have such a strict check because there are side configurations which throws a 200
# status code for every request.
if( ! res || res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

headers = http_extract_headers_from_response( data:res );
body = http_extract_body_from_response( data:res );
if( ! body || ! headers || headers !~ "Content-Type\s*:\s*text/html" )
  exit( 0 );

# nb: Body might only include newlines here so we need to strip them away before doing the check
# below.
body = chomp( body );

if( strlen( body ) == 0 ) {
  info["HTTP Method"] = "GET";
  info["Affected URL"] = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  report  = 'By doing the following HTTP request:\n\n';
  report += text_format_table( array:info ) + '\n\n';
  report += 'the response indicates that the system is exposing "wp-cron.php".\n\n';
  report += 'Note: Such systems reply with a 200 (OK), a text/html Content-Type and an empty body.';
  report += '\n\nResult:\n\n' + chomp( res );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 ); # nb: No exit(99); because the usage of wp-cron.php might be already disabled in WordPress...
