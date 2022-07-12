###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_citrix_xenmobile_detect.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Citrix XenMobile Server Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105569");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-15 18:31:10 +0100 (Tue, 15 Mar 2016)");
  script_name("Citrix XenMobile Server Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to extract
  the version number from the reply. When HTTP credentials are given, this script logis in into the XenMobile
  Server to get installed patch releases.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443, 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"XenMobile Username: ", value:"", type:"entry");
  script_add_preference(name:"XenMobile Password: ", type:"password", value:"");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");
include("misc_func.inc");

port = get_http_port( default:4443 );

url = '/zdm/login_xdm_uc.jsp';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>XenMobile" >!< buf || "Citrix Systems" >!< buf ) exit( 0 );

cpe = 'cpe:/a:citrix:xenmobile_server';
set_kb_item( name:"citrix_xenmobile_server/installed", value:TRUE );

cookie = http_get_cookie_from_header(buf: buf, pattern: "(JSESSIONID=[^;]+)");

if (cookie) {
  req = http_get_req(port: port, url: "/controlpoint/rest/xdmServices/general/version",
                     add_headers: make_array("X-Requested-With", "XMLHttpRequest",
                                             "Cookie", cookie,
                                             "Referer", report_vuln_url(port:port, url: url, url_only: TRUE)));

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf =~ 'HTTP/1.. 200' && "<message>" >< buf ) {
    status = eregmatch( pattern:'<status>([^<]+)</status>', string: buf );
    if( status[1] == 0 ) {
      version = eregmatch( pattern:'<message>([^<]+)</message>', string:buf );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        cpe += ':' + vers;
        replace_kb_item( name:"citrix_xenmobile_server/version", value:vers );
      }
    }
  }
}

register_product( cpe:cpe, location:'/', port:port );

user = script_get_preference( "XenMobile Username: " );
pass = script_get_preference( "XenMobile Password: " );

if( user && pass )
{
  login_credentials = TRUE;
  host = http_host_name( port:port );

  data = 'login=' + user + '&password=' + pass;
  len = strlen( data );

  url = "/zdm/cxf/login";
  ref = "/zdm/login_xdm_uc.jsp";
  req = http_post_req(port: port, url: url, data: data,
                      add_headers: make_array("X-Requested-With", "XMLHttpRequest",
                                              "Cookie", cookie,
                                              "Referer", report_vuln_url(port: port, url: ref, url_only: TRUE),
                                              "Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"),
                      accept_header: "application/json, text/javascript, */*; q=0.01");
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( '"status":"OK"' >< buf ) {
    cookie = http_get_cookie_from_header(buf: buf, pattern: "(JSESSIONID=[^;]+)");
    if (cookie) {
      url = '/controlpoint/rest/releasemgmt/allupdates';
      ref = '/index_uc.html';
      req = http_get_req(port: port, url: url,
                         add_headers: make_array("Cookie", cookie,
                                                 "Referer", report_vuln_url(port: port, url: ref, url_only: TRUE),
                                                 "X-Requested-With", "XMLHttpRequest"));

      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( '"message":"Success"' >< buf ) {
        login_success = TRUE;

        values = split( buf, sep:",", keep:FALSE );

        foreach val ( values )
          if( "release" >< val )
          {
            rv = eregmatch( pattern:'"release":"([0-9]+[^"]+)"', string:val );

            if( ! isnull( rv[1] ) )
              if( ! hv )
                hv = rv[1];
              else
                if( version_is_greater( version:rv[1], test_version:hv ) ) hv = rv[1];
          }
        }
    }
  }
}


report = 'Detected Citrix XenMobile Server\n' +
         'Version:  ' + vers + '\n' +
         'CPE:      ' + cpe + '\n' +
         'Location: /';

if( login_credentials )
{
  if( ! login_success )
    report += '\n\nIt was not possible to login into the remote Citrix XenMobile Server using the supplied HTTP credentials\n';
  else
    report += '\n\nIt was possible to login into the remote Citrix XenMobile Server using the supplied HTTP credentials\n';
}

if( hv )
{
  report += '\nHighest installed patch release: ' + hv + '\n';
  replace_kb_item( name:"citrix_xenmobile_server/patch_release", value:hv );
}
else
  if( login_credentials )
  {
    report += '\nNo patches installed\n';
    replace_kb_item( name:"citrix_xenmobile_server/patch_release", value:'no_patches' );
  }
  else
    report += '\n\nNo HTTP(s) credentials where given. Scanner was not able to to extract patch information from the application.\n';

log_message( port:port, data:report );

exit( 0 );

