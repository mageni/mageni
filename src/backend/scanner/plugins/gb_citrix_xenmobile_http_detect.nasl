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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105569");
  script_version("2022-09-15T11:47:44+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-15 11:47:44 +0000 (Thu, 15 Sep 2022)");
  script_tag(name:"creation_date", value:"2016-03-15 18:31:10 +0100 (Tue, 15 Mar 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix Endpoint Management / XenMobile Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Citrix Endpoint Management (formerly
  XenMobile).

  When HTTP credentials are given, this script logs into the Endpoint Management / XenMobile server
  to obtain the installed patch release information.");

  script_add_preference(name:"XenMobile Username: ", value:"", type:"entry", id:1);
  script_add_preference(name:"XenMobile Password: ", type:"password", value:"", id:2);

  script_xref(name:"URL", value:"https://docs.citrix.com/en-us/citrix-endpoint-management/endpoint-management.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");
include("version_func.inc");

port = http_get_port( default:443 );

url = "/zdm/login_xdm_uc.jsp";

res = http_get_cache( item:url, port:port );
if( ! res || "<title>XenMobile" >!< res || "Citrix Systems" >!< res )
  exit( 0 );

concl_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );

set_kb_item( name:"citrix/endpoint_management/detected", value:TRUE );
set_kb_item( name:"citrix/endpoint_management/http/detected", value:TRUE );

cookie = http_get_cookie_from_header( buf:res, pattern:"(JSESSIONID=[^;]+)" );

if( cookie ) {
  url = "/controlpoint/rest/xdmServices/general/version";

  req = http_get_req( port:port, url:url, referer_url:url,
                      add_headers:make_array( "X-Requested-With", "XMLHttpRequest",
                                              "Cookie", cookie ) );
  res = http_keepalive_send_recv( port:port, data:req );

  # <?xml version="1.0" encoding="UTF-8"?><result><message>10.10.0.7</message><status>0</status><result/></result>
  if( res =~ "^HTTP/1\.[01] 200" && "<message>" >< res ) {
    status = eregmatch( pattern:'<status>([^<]+)</status>', string:res );

    if( ! isnull( status[1] ) ) {
      vers = eregmatch( pattern:"<message>([^<]+)</message>", string:res );

      if( ! isnull( vers[1] ) ) {
        concl_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        version = vers[1];
      }
    }
  }
}

user = script_get_preference( "XenMobile Username: ", id:1 );
pass = script_get_preference( "XenMobile Password: ", id:2 );

if( user && pass ) {

  login_credentials = TRUE;
  host = http_host_name( port:port );

  data = "login=" + user + "&password=" + pass;
  url = "/zdm/cxf/login";
  ref = "/zdm/login_xdm_uc.jsp";
  req = http_post_put_req( port:port, url:url, data:data, referer_url:ref,
                           add_headers:make_array( "X-Requested-With", "XMLHttpRequest",
                                                   "Cookie", cookie,
                                                   "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8" ),
                           accept_header:"application/json, text/javascript, */*; q=0.01" );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( '"status":"OK"' >< buf ) {
    cookie = http_get_cookie_from_header( buf:buf, pattern:"(JSESSIONID=[^;]+)" );
    if( cookie ) {
      url = "/controlpoint/rest/releasemgmt/allupdates";
      ref = "/index_uc.html";
      req = http_get_req( port:port, url:url, referer_url:ref,
                          add_headers:make_array( "Cookie", cookie,
                                                  "X-Requested-With", "XMLHttpRequest" ) );

      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
      if( '"message":"Success"' >< buf ) {
        login_success = TRUE;

        values = split( buf, sep:",", keep:FALSE );

        foreach val( values ) {
          if( "release" >< val ) {
            rv = eregmatch( pattern:'"release":"([0-9]+[^"]+)"', string:val );
            if( ! isnull( rv[1] ) ) {
              if( ! hv )
                hv = rv[1];
              else {
                if( version_is_greater( version:rv[1], test_version:hv ) )
                  hv = rv[1];
              }
            }
          }
        }
      }
    }
  }
}

install = "/";
extra = "";

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:citrix:xenmobile_server:" );
if( ! cpe )
  cpe = "cpe:/a:citrix:xenmobile_server";

os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, desc:"Citrix XenMobile Server Detection (HTTP)", runs_key:"unixoide" );

register_product( cpe:cpe, location:install, port:port, service:"www" );

if( login_credentials ) {
  if( ! login_success )
    extra += '\n- It was not possible to login into the remote Citrix XenMobile Server using the supplied HTTP credentials.';
  else
    extra += '\n- It was possible to login into the remote Citrix XenMobile Server using the supplied HTTP credentials.';
} else {
  extra += '\n- No HTTP credentials where given. Scanner was not able to extract patch information from the application.';
}

if( hv ) {
  extra += '\n- Highest installed patch release: ' + hv + ' . Concluded from URL (authentication required): ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  replace_kb_item( name:"citrix_xenmobile_server/patch_release", value:hv );
} else {
  extra += '\n- No patches installed / detected.';
  if( login_success )
    extra += ' Concluded from URL (authentication required): ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  replace_kb_item( name:"citrix_xenmobile_server/patch_release", value:"no_patches" );
}

log_message( data:build_detection_report( app:"Citrix Endpoint Management / XenMobile", version:version,
                                          install:install, cpe:cpe, extra:extra, concludedUrl:concl_url,
                                          concluded:vers[0] ),
             port:port );

exit( 0 );
