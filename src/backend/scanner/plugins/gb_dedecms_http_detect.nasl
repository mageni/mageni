# Copyright (C) 2018 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.112300");
  script_version("2022-12-06T10:11:16+0000");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2018-06-11 11:32:22 +0200 (Mon, 11 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DedeCMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DedeCMS.");

  script_xref(name:"URL", value:"http://www.dedecms.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("dedecms_func.inc");

port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  res = http_get_cache( item: url, port: port );

  version = "unknown";
  found = FALSE;
  is_version_6 = FALSE;
  concluded = "";
  conclUrl = "";
  appName = "DedeCMS";
  # nb: There are 2 branches of the product, maintained by 2 different companies/ teams:
  # - continuation of V5.7 SP2 developed by https://www.dedecms.com/
  # - a V6 branch/ range of versions developed by  https://www.dedebiz.com/
  if( res =~ "^HTTP/(1\.[01]|2) 200" && ( "myajax = new DedeAjax(taget_obj,false,false,'','','');" >< res ||
      "/dedeajax2.js" >< res || "/dedecms.css" >< res || "dede_fields" >< res || "dede_fieldshash" >< res ) ) {
    appName += " V5.7 SP2";
    found = TRUE;

  } else if( res =~ "^HTTP/(1\.[01]|2) 200" && ( '<div class="dede-title">' >< res || "a href='https://www.dedebiz.com/'" >< res ) ) {

    appName += " V6";
    found = TRUE;
    is_version_6 = TRUE;
  }

  if ( found ) {

    set_kb_item( name: "dedecms/detected", value: TRUE );
    set_kb_item( name: "dedecms/http/detected", value: TRUE );

    url = dir + "/data/admin/ver.txt";

    res = http_get_cache( item: url, port: port );

    if( res =~ "^HTTP/(1\.[01]|2) 200" ) {

      body = http_extract_body_from_response( data: res );

      rel = eregmatch( pattern: "[0-9]{8}", string: body );

      if ( rel[0] ) {
        if ( is_version_6 )
          version = dedecms_version_6_release_date_to_version( rel: rel[0] );
        else
          version = dedecms_version_5_7_release_date_to_version( rel: rel[0] );
        concluded = rel[0];
        if ( conclUrl )
          conclUrl += '\n';
        conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
      }
    }

    cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:dedecms:dedecms:" );
    if ( ! cpe )
      cpe = 'cpe:/a:dedecms:dedecms';

    register_product( cpe: cpe, location: "/", port: port, service: "www" );

    report = build_detection_report( app: appName, version: version, install: install, cpe: cpe );

    if ( strlen( concluded ) > 0 )
      report += '\n\nConcluded from build date to version mapping:\n' + concluded;

    if( strlen( conclUrl ) > 0 )
      report += '\n\nConcluded from build date identification location:\n' + conclUrl;

    log_message( data: report ,
                 port: port );

    exit( 0 );
  }


}

exit( 0 );
