###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_imanager_detect.nasl 13952 2019-03-01 08:30:06Z ckuersteiner $
#
# Novell / NetIQ / Micro Focus iManager Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100434");
  script_version("$Revision: 13952 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:30:06 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-01-11 11:18:50 +0100 (Mon, 11 Jan 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Novell / NetIQ / Micro Focus iManager Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080, 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.novell.com/products/consoles/imanager/overview.html");
  script_xref(name:"URL", value:"https://www.microfocus.com/products/open-enterprise-server/features/imanager-network-administration-tool/");

  script_tag(name:"summary", value:"Detection of Novell / NetIQ / Micro Focus iManager.

  This host is running Novell / NetIQ / Micro Focus iManager, a Web-based administration console
  that provides customized access to network administration utilities and content from virtually any location.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

url = "/nps/servlet/webacc?taskId=dev.Empty&merge=fw.About";
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( isnull( buf ) ) exit( 0 );

if( buf =~ "^HTTP/1\.[01] 200" && ( "iManager" >< buf || "<title>NetIQ Access Manager" ><  buf ) ) {

  if( "NetIQ" >< buf ) {
    appname = "NetIQ iManager";
    basecpe = "cpe:/a:netiq:imanager";
  } else {
    appname = "Novell iManager";
    basecpe = "cpe:/a:novell:imanager";
  }

  version = "unknown";

  # http://www.novell.com/coolsolutions/tip/18634.html
  url = "/nps/version.jsp";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  vers = eregmatch( string:buf, pattern:"([0-9.]+)", icase:TRUE );

  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
  } else {
    url = "/nps/version.properties";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    # e.g. version=2.7.7.5 or version=3.0.3.2
    vers = eregmatch( string:buf, pattern:"version=([0-9.]+)", icase:TRUE );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    } else {
      url = "/nps/UninstallerData/installvariables.properties";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      # e.g. PRODUCT_NAME=NetIQ iManager 2.7.7
      # nb: This is less reliable as the version.properties is returning 2.7.7.5 on the same system
      # on e.g. newer releases of the NAM appliance we're even getting an 403/forbidden
      vers = eregmatch( string:buf, pattern:"PRODUCT_NAME=(NetIQ|Novell) iManager ([0-9.]+)", icase:TRUE );
      if( ! isnull( vers[2] ) ) {
        version = vers[2];
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  set_kb_item( name:"novellimanager/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"([0-9.]+)", base:basecpe + ":" );
  if( !cpe )
    cpe = basecpe;

  register_product( cpe:cpe, location:"/", port:port );

  log_message( data:build_detection_report( app:appname,
                                            version:version,
                                            install:"/",
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
               port:port );
}

exit( 0 );
