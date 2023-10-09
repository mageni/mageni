# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112798");
  script_version("2023-09-29T05:05:51+0000");
  script_tag(name:"last_modification", value:"2023-09-29 05:05:51 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"creation_date", value:"2020-08-06 12:04:11 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Themes Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_wordpress_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/http/detected");

  script_tag(name:"summary", value:"HTTP based detection of WordPress themes.");

  script_xref(name:"URL", value:"https://wordpress.org/themes/");

  script_timeout(900);

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("wordpress_themes.inc");

if( ! port = get_app_port( cpe: CPE, service: "www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

foreach style_file( keys( wordpress_themes_info ) ) {

  infos = wordpress_themes_info[style_file];
  if( ! infos )
    continue;

  infos = split( infos, sep: "#---#", keep: FALSE );
  if( ! infos || max_index( infos ) < 4 )
    continue;

  name = infos[0];
  detect_regex = infos[1];
  vers_regex = infos[2];
  cpe = infos[3] + ":";
  theme_url = infos[4];
  extra = "";

  url = dir + "/wp-content/themes/" + style_file;
  res = http_get_cache( port: port, item: url );

  if( ( concl = egrep( pattern: detect_regex, string: res, icase: TRUE ) ) && "Theme URI:" >< res ) {

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

    kb_entry_name = ereg_replace( pattern: "/style.css", string: tolower( style_file ), replace: "", icase: TRUE );
    insloc = ereg_replace( pattern: "/style.css", string: url, replace: "", icase: TRUE );

    # nb: Usually only the one without the "/http/" should be used for version checks.
    set_kb_item( name: "wordpress/theme/" + kb_entry_name + "/detected", value: TRUE );
    set_kb_item( name: "wordpress/theme/http/" + kb_entry_name + "/detected", value: TRUE );
    # nb: Some generic KB keys if we ever need to run this if multiple themes have been detected.
    set_kb_item( name: "wordpress/theme/detected", value: TRUE );
    set_kb_item( name: "wordpress/theme/http/detected", value: TRUE );

    if( theme_url )
      extra = "Theme Page: " + theme_url;
    else
      extra = "Theme Page: https://wordpress.org/themes/" + kb_entry_name + "/";

    register_and_report_cpe( app: "WordPress Theme '" + name + "'",
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
