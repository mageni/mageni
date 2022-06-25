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
  script_oid("1.3.6.1.4.1.25623.1.0.113117");
  script_version("2021-12-07T13:21:50+0000");
  script_tag(name:"last_modification", value:"2021-12-08 11:02:40 +0000 (Wed, 08 Dec 2021)");
  script_tag(name:"creation_date", value:"2018-02-20 13:31:37 +0100 (Tue, 20 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Kentico CMS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Kentico CMS.");

  script_xref(name:"URL", value:"https://www.kentico.com");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  res = http_get_cache( port: port, item: url );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  if( '<meta name="generator" content="Kentico' >< res ||
        # e.g.:
        # Set-Cookie: CMSPreferredCulture=en-IE; expires=Tue, 27-Sep-2022 13:26:44 GMT; path=/; HttpOnly
        # Set-Cookie: CMSCsrfCookie=piTqvHE31YUcIlQloRT5M9GyKlP13n0xHY5xCBjO; path=/; HttpOnly
        # Set-Cookie: CMSCurrentTheme=MyTheme; expires=Tue, 28-Sep-2021 13:26:44 GMT; path=/; HttpOnly
        # Set-Cookie: CMSCookieLevel=0; expires=Tue, 27-Sep-2022 13:26:44 GMT; path=/; HttpOnly
      ( egrep( string: res, pattern: "^[Ss]et-[Cc]ookie\s*:\s*CMS(PreferredCulture|CsrfCookie|CurrentTheme|CookieLevel)=.+", icase: FALSE ) &&
        # e.g.:
        # <script src="/CMSPages/GetResource.ashx?scriptfile=%7e%2fCMSScripts%2fWebServiceCall.js" type="text/javascript"></script>
        # <link href="/CMSPages/GetResource.ashx?stylesheetfile=/App_Themes/MyTheme/bootstrap.css" type="text/css" rel="stylesheet" />
        # "imagesUrl": "/CMSPages/GetResource.ashx?image=%5bImages.zip%5d%2f",
        egrep( string: res, pattern: '(<(link href|script src)=|"imagesUrl"\\s*:\\s*)"[^"]*/CMSPages/GetResource\\.ashx\\?', icase: FALSE )
      ) ) {

    version = "unknown";
    vers = eregmatch( string: res, pattern: 'content="Kentico [CMS ]{0,4}[0-9.(betaR)?]+ \\(build ([0-9.]+)\\)', icase: TRUE );

    if( ! isnull( vers[1] ) )
      version = vers[1];

    set_kb_item( name: "kentico_cms/detected", value: TRUE );
    set_kb_item( name: "kentico_cms/http/detected", value: TRUE );

    cpe1 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kentico:kentico:" );
    cpe2 = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:kentico:kentico_cms:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:kentico:kentico";
      cpe2 = "cpe:/a:kentico:kentico_cms";
    }

    register_product( cpe: cpe1, location: install, port: port, service: "www" );
    register_product( cpe: cpe2, location: install, port: port, service: "www" );

    log_message( data: build_detection_report( app: "Kentico CMS",
                                               version: version,
                                               cpe: cpe1,
                                               install: install,
                                               concluded: vers[0],
                                               concludedUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) ),
                 port: port );

    exit( 0 ); # nb: Avoid multiple detections on different sub-pages
  }
}

exit( 0 );