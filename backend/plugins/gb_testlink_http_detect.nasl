# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100389");
  script_version("2021-12-14T05:35:35+0000");
  script_tag(name:"last_modification", value:"2021-12-15 11:21:53 +0000 (Wed, 15 Dec 2021)");
  script_tag(name:"creation_date", value:"2009-12-10 18:09:58 +0100 (Thu, 10 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("TestLink Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of TestLink.");

  script_xref(name:"URL", value:"https://testlink.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( !http_can_host_php( port:port ) )
  exit(0);

foreach dir( make_list_unique( "/testlink", http_cgi_dirs( port:port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/login.php";
  buf = http_get_cache( item:url, port:port );
  if( !buf )
    continue;

  if( ( egrep( pattern:"<title>TestLink( - Login)?</title>", string:buf, icase:TRUE ) &&
        ( egrep( pattern:"TestLink is licensed under the", string:buf ) ||
        egrep( pattern:"Please log in", string:buf ) ) ) ||
      ( 'for="tl_password">' >< buf && 'for="tl_login">' >< buf ) ) {
    version = "unknown";
    concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    url = dir + "/CHANGELOG";
    res = http_get_cache( port:port, item:url );

    # TestLink - 1.9.19 (2019 Q1) (Released 2019 Week 04)
    # Testlink 1.7.4
    vers = eregmatch( pattern:"Test[Ll]ink (- )?([0-9.]+)", string:res, icase:FALSE );
    if( res !~ "^HTTP/1\.[01] 200" || isnull( vers[2] ) ) {
      # <div class="title"><img alt="TestLink" title="TestLink" src="gui/themes/theme_m1/images/company_logo.png" /><br />TestLink 1.7.4</div>
      # or:
      # <p><img alt="Company logo" title="logo" src="gui/themes/default/images/tl-logo-transparent-25.png" />
      #   <br />1.9.14 (Padawan)</p>
      vers = eregmatch( string:buf, pattern:"TestLink[Prague ]{0,7} ([0-9.]+)", icase:TRUE );
      if( isnull( vers[1] ) )
        vers = eregmatch( string:buf, pattern:'<br[ ]?/>([0-9.]+) \\([A-Za-z]+\\)</p>', icase:TRUE );

      if( !isnull( vers[1] ) ) {
        version = vers[1];
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    } else {
      version = vers[2];
      concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    set_kb_item( name:"testlink/detected", value:TRUE );
    set_kb_item( name:"testlink/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:testlink:testlink:" );
    if( !cpe )
      cpe = "cpe:/a:testlink:testlink";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"TestLink", version:version, install:install, cpe:cpe,
                                              concluded:vers[0], concludedUrl:concUrl ),
                 port:port );
    exit(0);
  }
}

exit(0);
