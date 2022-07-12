###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitecore_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Sitecore CMS Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108191");

  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");

  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-10-16 15:54:00 +0200 (Mon, 16 Oct 2017)");

  script_name("Sitecore CMS Detection");

  script_tag(name:"summary", value:"Detection of Sitecore CMS.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "cpe.inc" );
include( "host_details.inc" );

port = get_http_port( default:80 );
found = FALSE;

foreach dir( make_list_unique( "/", "/sitecore", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/login/", port:port );

  if( res =~ "^HTTP/1\.[01] 200" &&
      ( 'Sitecore' >< res || 'sitecore' >< res ) &&
      ( '<img id="BannerLogo" src="/sitecore/login/logo.png" alt="Sitecore Logo"' >< res ||
        '<form method="post" action="/sitecore/login' >< res ||
        'href="/sitecore/login/login.css"' >< res ) ) {

    found = TRUE;
    version = "unknown";

    if( ! ver = eregmatch( pattern:"Sitecore version.*\(Sitecore ([0-9.]+)\)", string:res ) )
      if( ! ver = eregmatch( pattern:"Sitecore\.NET ([0-9.]+) \(rev\. ([0-9.]+) Hotfix ([0-9\-]+)\)", string:res ) )
        if( ! ver = eregmatch( pattern:"Sitecore\.NET ([0-9.]+) \(rev\. ([0-9.]+)\)", string:res ) )
          ver = eregmatch( pattern:"Sitecore\.NET ([0-9.]+)", string:res );

    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      concUrl = report_vuln_url(  port:port, url:dir + "/login/", url_only:TRUE );
    }
    if( ! isnull( ver[2] ) ) extra += 'Revision: ' + ver[2];
    if( ! isnull( ver[3] ) ) extra += '\nHotfix: ' + ver[3];

    if( found ){

      cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sitecore:cms:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:sitecore:cms";

      set_kb_item( name:"sitecore/cms/installed", value:TRUE );

      register_product( cpe:cpe, location:install, port:port );

      log_message( data: build_detection_report( app:"Sitecore CMS",
                                                 version:version,
                                                 install:install,
                                                 cpe:cpe,
                                                 concluded:ver[0],
                                                 concludedUrl:concUrl,
                                                 extra:extra ),
                                                 port:port );
      exit(0);
    }
  }
}
