# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113249");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-08-22 11:46:47 +0200 (Wed, 22 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Home Assistant Dashboard Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8123, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Home Assistant Smart Home Dashboard.");

  script_xref(name:"URL", value:"https://www.home-assistant.io/");

  exit(0);
}

CPE = "cpe:/a:home-assistant:home-assistant:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("os_func.inc");

port = http_get_port( default: 8123 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";

  buf = http_get_cache( port: port, item: url );
  # nb: eregmatch() is used here so that we're not reporting "too" much later
  if( buf =~ "^HTTP/(2|1\.[01]) 200" && ( concl = eregmatch( string: buf, pattern: "<title>Home Assistant<", icase: FALSE ) ) ) {

    version = "unknown";

    set_kb_item( name: "home_assistant/detected", value: TRUE );
    set_kb_item( name: "home_assistant/http/detected", value: TRUE );
    set_kb_item( name: "home_assistant/port", value: port );

    conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
    concluded = concl[0];

    url = dir + "/api/discovery_info";
    buf = http_get_cache( port: port, item: url );

    if( buf =~ "^HTTP/(2|1\.[01]) 200" ) {
      # eg. "version": "2021.4.0"
      vers = eregmatch( pattern: '"version":\\s*"([0-9.]+)"', string: buf );
      if( vers[1] ) {
        version = vers[1];
        concluded += '\n' + vers[0];
        conclUrl += '\n' + http_report_vuln_url( port: port, url: url, url_only: TRUE );
      }

      if( buf =~ "Home Assistant OS" ) {
        os_name = "Home Assistant OS";
        # nb: NVD has no dedicated CPE for the OS, used same format as for App
        os_cpe = "cpe:/o:home-assistant:home-assistant";
      } else {
        os_name = "Linux/Unix";
        os_cpe = "cpe:/o:linux:kernel";
      }

      os_register_and_report( os: os_name, cpe: os_cpe, port: port,
                              banner_type: "Home Assistant Dashboard Page",
                              desc: "Home Assistant Dashboard Detection (HTTP)", runs_key: "unixoide" );
    }

    register_and_report_cpe( app: "Home Assistant",
                             ver: version,
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: install,
                             regPort: port,
                             conclUrl: conclUrl,
                             concluded: concluded );

    exit( 0 );
  }
}

exit( 0 );
