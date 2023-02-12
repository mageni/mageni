# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100434");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Novell / NetIQ / Micro Focus iManager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Novell / NetIQ / Micro Focus iManager.");

  script_xref(name:"URL", value:"http://www.novell.com/products/consoles/imanager/overview.html");
  script_xref(name:"URL", value:"https://www.microfocus.com/products/open-enterprise-server/features/imanager-network-administration-tool/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:8443 );

url = "/nps/servlet/webacc?taskId=dev.Empty&merge=fw.About";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( res =~ "HTTP/1\.[01] 200" && ( res =~ "<title>(NetIQ )?iManager" || 'name="Login_Key"' >< res ) ) {
  version = "unknown";

  # http://www.novell.com/coolsolutions/tip/18634.html
  url = "/nps/version.jsp";

  req = http_get( port:port, item:url );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  vers = eregmatch( string:res, pattern:"([0-9.]+)" );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  } else {
    url = "/nps/version.properties";

    res = http_get_cache( port:port, item:url );
    # e.g. version=2.7.7.5 or version=3.0.3.2
    vers = eregmatch( string:res, pattern:"version=([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    } else {
      url = "/nps/UninstallerData/installvariables.properties";
      res = http_get_cache( port:port, item:url );

      # e.g. PRODUCT_NAME=NetIQ iManager 2.7.7
      # nb: This is less reliable as the version.properties is returning 2.7.7.5 on the same system
      # on e.g. newer releases of the NAM appliance we're even getting an 403/forbidden
      vers = eregmatch( string:res, pattern:"PRODUCT_NAME=(NetIQ|Novell) iManager ([0-9.]+)", icase:TRUE );
      if( ! isnull( vers[2] ) ) {
        version = vers[2];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  set_kb_item( name:"netiq/imanager/detected", value:TRUE );
  set_kb_item( name:"netiq/imanager/http/detected", value:TRUE );

  cpe1 = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:netiq:imanager:" );
  cpe2 = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:novell:imanager:" );
  if( ! cpe1 ) {
    cpe1 = "cpe:/a:netiq:imanager";
    cpe2 = "cpe:/a:novell:imanager";
  }

  register_product( cpe:cpe1, location:"/", port:port, service:"www" );
  register_product( cpe:cpe2, location:"/", port:port, service:"www" );

  log_message( data:build_detection_report( app:"Novell / NetIQ / Micro Focus iManager",
                                            version:version,
                                            install:"/",
                                            cpe:cpe1,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
               port:port );
}

exit( 0 );
