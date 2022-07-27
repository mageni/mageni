# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117498");
  script_version("2021-06-16T13:40:04+0000");
  script_tag(name:"last_modification", value:"2021-06-17 10:43:15 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-16 12:20:23 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("FCKeditor Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.fckeditor.net");

  script_tag(name:"summary", value:"HTTP based detection of FCKeditor.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:80 );

cgidirs = make_list_unique( "/", http_cgi_dirs( port:port ) );
subdirs = make_list( "/", "/fckeditor", "/editor",
                     "/admin/fckeditor",
                     "/sites/all/modules/fckeditor",
                     "/resources/fckeditor",
                     "/clientscript/fckeditor",
                     "/wp-content/plugins/fckeditor-for-wordpress/fckeditor" );
foreach cgidir( cgidirs ) {
  foreach subdir( subdirs ) {
    # To avoid doubled calls and calls like //dir
    if( cgidir != "/" && subdir == "/" )
      subdir = "";
    if( cgidir == "/" )
      cgidir = "";
    dirs = make_list_unique( dirs, cgidir + subdir );
  }
}

foreach dir( dirs ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/fckeditor.js";
  buf = http_get_cache( item:url, port:port );
  url2 = dir + "/_whatsnew.html";
  buf2 = http_get_cache( item:url2, port:port );

  if( ( buf =~ "^HTTP/1\.[01] 200" &&
        ( "* FCKeditor - The text editor for Internet" >< buf ||
          "var FCKeditor = function(" >< buf ) ) ||
      ( buf2 =~ "^HTTP/1\.[01] 200" && "<title>FCKeditor ChangeLog - What's New?</title>" >< buf2 ) ) {

    version = "unknown";

    # FCKeditor.prototype.Version                       = '2.6' ;
    # FCKeditor.prototype.Version                       = '[Development]' ;
    # nb: The strings above had three tabs which got replaced in this VT by spaces.
    ver = eregmatch( pattern:'FCKeditor\\.prototype\\.Version\\s*=\\s*["\']([0-9.]+)["\']', string:buf, icase:FALSE );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    # Version 2.6.6</h3>
    # Version 2.6</h3>
    # Version 2.6 RC</h3>
    if( version == "unknown" && buf2 =~ "^HTTP/1\.[01] 200" ) {
      ver = eregmatch( pattern:"\s+Version ([0-9.]+)[^<]*</h3>", string:buf2, icase:FALSE );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
        conclUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      }
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:fckeditor:fckeditor:" );
    if( ! cpe )
      cpe = "fcpe:/a:fckeditor:fckeditor";

    set_kb_item( name:"fckeditor/detected", value:TRUE );
    set_kb_item( name:"fckeditor/http/detected", value:TRUE );
    set_kb_item( name:"ckeditor_or_fckeditor/detected", value:TRUE );
    set_kb_item( name:"ckeditor_or_fckeditor/http/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"FCKeditor",
                                              version:version,
                                              concluded:ver[0],
                                              concludedUrl:conclUrl,
                                              install:install,
                                              cpe:cpe ),
                                              port:port );
  }
}

exit( 0 );