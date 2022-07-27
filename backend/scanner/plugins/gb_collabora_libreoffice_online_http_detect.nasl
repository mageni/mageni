# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108000");
  script_version("2021-11-30T10:55:08+0000");
  script_tag(name:"last_modification", value:"2021-12-01 11:00:55 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2016-09-15 09:00:00 +0200 (Thu, 15 Sep 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Collabora / LibreOffice Online Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9980);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://wiki.documentfoundation.org/Development/LibreOffice_Online");
  script_xref(name:"URL", value:"https://www.collaboraoffice.com/code/");

  script_tag(name:"summary", value:"HTTP based detection of Collabora / LibreOffice Online.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:9980 );
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/hosting/discovery";
  buf = http_get_cache( item:url, port:port );

  # nb: User-Agent / Server banner depends on the queried endpoint. We're just adding all of them
  # just to be sure...
  # User-Agent: LOOLWSD HTTP Agent 6.4.10
  # User-Agent: LOOLWSD WOPI Agent 4.2.15
  # User-Agent: COOLWSD HTTP Agent 21.11.0.3
  # User-Agent: LOOLWSD WOPI Agent
  # Server: COOLWSD HTTP Server 21.11.0.3
  if( buf =~ "^HTTP/1\.[01] 200" && ( buf =~ "(User-Agent|Server)\s*:\s*[CL]OOLWSD (WOPI|HTTP) (Agent|Server)" ||
      ( "wopi-discovery" >< buf && "application/vnd." >< buf && buf =~ "(cool|loleaflet)\.html" ) ) ) {

    version = "unknown";
    concludedUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    # nb: Newer versions are only using a hash in the URL like
    # <action default="true" ext="odt" name="edit" urlsrc="https://127.0.0.1:9980/loleaflet/078e8b8/loleaflet.html?"/>
    # <action default="true" ext="ott" name="edit" urlsrc="https://127.0.0.1:9980/browser/b5534c4/cool.html?"/>
    verUrl = egrep( string:buf, pattern:'<action (default="true" )?ext="(odt|odp|ott|ods)" name="[^"]+" urlsrc=".*"/>', icase:TRUE );
    # nb: The regex is used strict like this so that we're not accidentally matching something unexpected.
    vers = eregmatch( string:verUrl, pattern:'urlsrc="https?://[^"]+/(loleaflet|browser)/([0-9]+\\.[0-9]+\\.[0-9.]+)/[^"]+"/>', icase:TRUE );
    if( vers[2] )
      version = vers[2];

    if( version == "unknown" ) {
      url = dir + "/hosting/capabilities";
      buf = http_get_cache( item:url, port:port );
      if( buf && buf =~ "^HTTP/1\.[01] 200" ) {

        # {"convert-to":{"available":true,"endpoint":"/cool/convert-to"},"hasMobileSupport":true,"hasProxyPrefix":false,"hasTemplateSaveAs":false,"hasTemplateSource":true,"productName":"Collabora Online","productVersion":"21.11.0.3snapshot","productVersionHash":"3caec5a"}
        # {"convert-to":{"available":true,"endpoint":"/cool/convert-to"},"hasMobileSupport":true,"hasProxyPrefix":false,"hasTemplateSaveAs":false,"hasTemplateSource":true,"productName":"Collabora Online Development Edition","productVersion":"21.11.0.3","productVersionHash":"b5534c4"}
        # {"convert-to":{"available":true},"hasMobileSupport":true,"hasProxyPrefix":false,"hasTemplateSaveAs":false,"hasTemplateSource":true,"productName":"Collabora Online Development Edition","productVersion":"6.4.13","productVersionHash":"078e8b8"}
        # {"convert-to":{"available":false},"hasMobileSupport":true,"hasProxyPrefix":false,"hasTemplateSaveAs":false,"hasTemplateSource":true,"productName":"Collabora Online","productVersion":"4.2.17","productVersionHash":"bba3d85"}
        # but also seen this "live":
        # {"convert-to":{"available":true},"hasMobileSupport":true,"hasTemplateSaveAs":true,"hasTemplateSource":true,"productName":"OxOOL"}
        vers = eregmatch( string:buf, pattern:'"productVersion"\\s*:\\s*"([^"]+)"', icase:FALSE );
        if( vers[1] ) {
          version = vers[1];
          concludedUrl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    # nb: Basic auth check for default_http_auth_credentials.nasl
    foreach url( make_list( dir + "/dist/admin/admin.html", dir + "/loleaflet/dist/admin/admin.html", dir + "/browser/dist/admin/admin.html" ) ) {

      buf = http_get_cache( item:url, port:port );

      if( buf && buf =~ "^HTTP/1\.[01] 401" ) {
        set_kb_item( name:"www/content/auth_required", value:TRUE );
        set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
        extra = 'Password protected admin backend is available at:\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
        break;
      }
    }

    set_kb_item( name:"collabora_libreoffice/online/detected", value:TRUE );
    set_kb_item( name:"collabora_libreoffice/online/http/detected", value:TRUE );

    cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:collabora:online:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:collabora:libreofficeonline:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:collabora:online";
      cpe2 = "cpe:/a:collabora:libreofficeonline";
    }

    register_product( cpe:cpe1, location:install, port:port, service:"www" );
    register_product( cpe:cpe2, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Collabora / LibreOffice Online",
                                              version:version,
                                              install:install,
                                              cpe:cpe1,
                                              concluded:vers[0],
                                              concludedUrl:concludedUrl,
                                              extra:extra ),
                                              port:port );
  }
}

exit( 0 );