###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_geoserver_detect.nasl 8144 2017-12-15 13:19:55Z cfischer $
#
# GeoServer Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Verendra GG <verendragg@secpod.com> on 2010-04-28
# Updated the detection logic
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900945");
  script_version("$Revision: 8144 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:19:55 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("GeoServer Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://geoserver.org/");

  script_tag(name:"summary", value:"This script detects the installed version of GeoServer and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function register_and_report( ver, dir, port, cpe, concluded, conclUrl )
{
  set_kb_item(name:"www/" + port + "/GeoServer",  value:ver + " under " + dir );
  set_kb_item(name:"GeoServer/installed", value:TRUE);

  register_product( cpe:cpe, location:dir, port:port );
  log_message( data: build_detection_report( app:"GeoServer",
                                             version:ver,
                                             install:dir,
                                             cpe:cpe,
                                             concludedUrl:conclUrl,
                                             concluded:concluded),
               port:port);
  exit( 0 );
}

geoPort = get_http_port( default:80 );

cpe = 'cpe:/a:geoserver:geoserver';

dirs = make_list_unique("/", "/geoserver", cgi_dirs(port:geoPort));

foreach dir ( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  path = dir + "/welcome.do";
  sndReq = http_get(item:path, port:geoPort);
  rcvRes = http_keepalive_send_recv( port:geoPort, data:sndReq, bodyonly:FALSE );

  ## Logic for version lesser then 2.0
  if(("My GeoServer" >< rcvRes) && ("Welcome to GeoServer" >< rcvRes))
  {
    ## Matches 1.7.0 or 1.7.0-RC1 or 1.7.0-beta1
    geoVer = eregmatch(pattern:"Welcome to GeoServer ([0-9.]+(-[a-zA-Z0-9]+)?)", string:rcvRes);
    if( ! isnull( geoVer[1] ) )
    {
      concluded = geoVer[0];
      ## to remove "." at the end
      geoVer = ereg_replace(pattern:"([0-9]\.[0-9]\.[0-9])\.", string:geoVer[1], replace:"\1");
      ## Replacing "-" with "." ex 1.7.0-RC1 and 1.7.0-beta1
      geoVer = ereg_replace(pattern:"-", replace:".", string:geoVer);

      cpe = cpe + ':' + geoVer;
    }
    else
      geoVer = 'unknown';

    register_and_report( ver:geoVer, dir:install, port:geoPort, cpe:cpe, concluded:concluded );

  }
}

## Logic for version 2.0
foreach dir ( dirs ) {

  install = dir;
  if( dir == "/" ) dir = "";

  path = dir +  "/web/?wicket:bookmarkablePage=:org.geoserver.web.AboutGeoServerPage";
  conclUrl = report_vuln_url( port:geoPort, url:path, url_only:TRUE );
  sndReq = http_get(item:path, port:geoPort);
  rcvRes = http_keepalive_send_recv(port:geoPort, data:sndReq);

  if(("<title>GeoServer: About GeoServer" >< rcvRes))
  {
    ## Matches 2.0.1 or 2.0.1-RC1 or 2.0.1-beta1
    geoVer = eregmatch(pattern:">GeoServer ([0-9]\.[0-9]\.[0-9](-[a-zA-Z0-9]+)?)<", string:rcvRes);
    if( isnull( geoVer[1] ) )
      geoVer = eregmatch( pattern:'span id="version">([^<]+)<', string:rcvRes );

    if( ! isnull( geoVer[1] ) )
    {
      concluded = geoVer[0];
      ## to remove "." at the end
      geoVer = ereg_replace(pattern:"([0-9]\.[0-9]\.[0-9])\.", string:geoVer[1], replace:"\1");
      ## Replacing "-" with "." ex 1.7.0-RC1 and 1.7.0-beta1
      geoVer = ereg_replace(pattern:"-", replace:".", string:geoVer);

      cpe = cpe + ':' + geoVer;
    }
    else
      geoVer = 'unknown';

    register_and_report( ver:geoVer, dir:install, port:geoPort, cpe:cpe, concluded:concluded, conclUrl:conclUrl );

  }
}

exit( 0 );
