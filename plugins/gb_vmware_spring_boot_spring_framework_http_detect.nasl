# Copyright (C) 2022 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113866");
  script_version("2022-04-04T06:22:18+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-04 10:02:40 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-31 10:26:06 +0000 (Thu, 31 Mar 2022)");
  script_name("VMware Spring Boot / Spring Framework Detection (HTTP)");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://spring.io/projects/spring-framework");
  script_xref(name:"URL", value:"https://spring.io/projects/spring-boot");

  script_tag(name:"summary", value:"HTTP based detection of VMware Spring Boot and the Spring
  Framework.");

  script_tag(name:"vuldetect", value:"Sends various crafted HTTP GET requests and checks if an error
  message of the Spring Boot component is returned which is used to determine if the Spring
  Framework or one of it's component is installed on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

urls = make_list( "/error", # Default endpoint, see e.g. https://mkyong.com/spring-boot/spring-rest-error-handling-example/
                  "/vt-test-non-existent.html",
                  "/vt-test/vt-test-non-existent.html", # nb: Just two additional default ones
                  "/tenant-app-api/" ); # nb: On the "vRealize Operations Tenant App for VMware Cloud Director" the detection happens only on this URL

# nb: Adding various dirs, on specific installations the detection might only happen on these (see above).
foreach dir( http_cgi_dirs( port:port ) ) {

  if( dir == "/" )
    dir = "";

  urls = make_list( dir + "/", urls );
}

urls = make_list_unique( urls );

concluded = ""; # nb: To make openvas-nasl-lint happy...
conclUrl = ""; # nb: To make openvas-nasl-lint happy...
reporting_count = 0;

foreach url( urls ) {

  res = http_get_cache( item:url, port:port, fetch404:TRUE );
  if( ! res || res !~ "^HTTP/1\.[01] (500|404)" ) # nb: See note on the status codes below
    continue;

  headers = http_extract_headers_from_response( data:res );
  body = http_extract_body_from_response( data:res );
  if( ! headers || ! body ||
      ! egrep( string:headers, pattern:"^[Cc]ontent-[Tt]ype\s*:\s*application/json", icase:FALSE ) ) # nb: See note on the content-type below
    continue;

  # The "/error" endpoint should always throw something like the following by default:
  #
  # {"timestamp":"2022-03-31T10:38:19.688+00:00","status":999,"error":"None"}
  #
  # with a 500 status code while others are throwing something like e.g.:
  #
  # {"timestamp":"2022-03-31T11:16:43.590+0000","status":404,"error":"Not Found","message":"No message available","path":"/tenant-app-api/"}
  #
  # or:
  #
  # {"timestamp":"2022-03-31T11:38:58.209+00:00","status":404,"error":"Not Found","path":"/tenant-app-api/"}
  #
  # with a 404 status code. All of them have a application/json content type.
  #
  # To have a quite strict check (avoid false positive detections) we're differentiating between the
  # pattern here. This might be not optimal if the messages could be translated but no such info
  # about the possibility to translate them have been found.

  if( headers =~ "^HTTP/1\.[01] 500" )
    pattern = '^\\s*\\{"timestamp":"[^"]+","status":999,"error":"None"\\}';
  else
    pattern = '^\\s*\\{"timestamp":"[^"]+","status":404,"error":"Not Found",("message":"No message available",)?"path":"' + url + '"\\}';

  if( concl = egrep( string:body, pattern:pattern, icase:FALSE ) ) {

    found = TRUE;
    reporting_count++;

    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    if( concluded )
      concluded += '\n';
    concluded += "  " + chomp( concl );
  }

  if( reporting_count > 2 ) # nb: No need for a huge reporting...
    break;
}

if( found ) {

  version = "unknown";
  install = "/";

  set_kb_item( name:"vmware/spring/framework/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/framework/http/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/boot/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/boot/http/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/boot_or_framework/detected", value:TRUE );
  set_kb_item( name:"vmware/spring/boot_or_framework/http/detected", value:TRUE );

  # nb: Spring Boot is internally using the Spring Framework
  cpe1 = "cpe:/a:vmware:spring_framework";
  cpe2 = "cpe:/a:vmware:spring_boot";

  register_product( cpe:cpe1, location:install, port:port, service:"www" );
  register_product( cpe:cpe2, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"VMware Spring Boot / Spring Framework",
                                            version:version,
                                            install:install,
                                            cpe:cpe1 + " / " + cpe2,
                                            concluded:concluded,
                                            concludedUrl:conclUrl ),
               port:port );
}

exit( 0 );
