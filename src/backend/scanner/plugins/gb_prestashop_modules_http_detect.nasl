# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127559");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-19 07:40:33 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PrestaShop Modules Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_prestashop_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("prestashop/http/detected");

  script_tag(name:"summary", value:"HTTP based detection of PrestaShop modules.");

  script_xref(name:"URL", value:"https://addons.prestashop.com");

  script_timeout(900);

  exit(0);
}

CPE = "cpe:/a:prestashop:prestashop";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("prestashop_modules.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach module( keys( prestashop_modules_info ) ) {

  if( ! infos = prestashop_modules_info[module] )
    continue;

  infos = split( infos, sep: "#---#", keep: FALSE );
  if( ! infos || max_index( infos ) < 4 )
    continue;

  name = infos[0];
  detect_regex = infos[1];
  vers_regex = infos[2];
  cpe = infos[3] + ":";
  module_page = infos[4];

  url = dir + "/modules/" + module + "/config.xml";
  res = http_get_cache( port: port, item: url );

  if( concl = egrep( pattern: detect_regex, string: res, icase: TRUE ) ) {

    version = "unknown";
    # nb: Minor formatting change for the reporting.
    concl = chomp( concl );
    concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
    concluded = "  " + concl;

    vers = eregmatch( pattern: vers_regex, string: res, icase: TRUE );
    if( vers[1] ) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }

    kb_entry_name = module;
    insloc = ereg_replace( pattern: "/config\.xml", string: url, replace: "", icase: TRUE );

    # nb: Usually only the one without the "/http/" should be used for version checks.
    set_kb_item( name: "prestashop/module/" + kb_entry_name + "/detected", value: TRUE );
    set_kb_item( name: "prestashop/module/http/" + kb_entry_name + "/detected", value: TRUE );
    # nb: Some generic KB keys if we ever need to run this if multiple modules have been detected.
    set_kb_item( name: "prestashop/module/detected", value: TRUE );
    set_kb_item( name: "prestashop/module/http/detected", value: TRUE );

    extra = "Module Page: https://addons.prestashop.com/" + module_page + ".html";

    register_and_report_cpe( app: "PrestaShop Module '" + name + "'",
                             ver: version,
                             concluded: concluded,
                             base: cpe,
                             expr: "([0-9.]+)",
                             insloc: insloc,
                             regPort: port,
                             regService: "www",
                             conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ),
                             extra: extra );
  }
}

exit( 0 );
