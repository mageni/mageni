# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:docker:docker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104831");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"creation_date", value:"2023-07-12 12:09:10 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Docker HTTP REST API Public WAN (Internet) / Public LAN Accessible without Authentication");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_docker_http_rest_api_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("docker/http/rest-api/noauth", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://docs.docker.com/engine/security/protect-access/#use-tls-https-to-protect-the-docker-daemon-socket");

  script_tag(name:"summary", value:"The script checks if the target host is exposing the Docker HTTP
  REST API endpoints to a public WAN (Internet) / public LAN without authentication.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is exposing the Docker HTTP REST
  API endpoints to a public WAN (Internet) / public LAN without authentication.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"solution", value:"Only allow access to the Docker HTTP REST API endpoints from
  trusted sources or enable authentication via client certificates.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

if( ! is_public_addr() )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! get_kb_item( "docker/http/rest-api/" + port + "/noauth" ) )
  exit( 99 );

accessible_endpoints = get_kb_item( "docker/http/rest-api/" + port + "/accessible_endpoints" );
if( accessible_endpoints )
  report = 'Accessible endpoint(s):\n' + accessible_endpoints;

security_message( port:port, data:report );
exit( 0 );
