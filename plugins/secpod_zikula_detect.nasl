##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zikula_detect.nasl 14168 2019-03-14 08:10:09Z cfischer $
#
# Zikula / PostNuke Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900620");
  script_version("$Revision: 14168 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-06-02 12:54:52 +0200 (Tue, 02 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Zikula / PostNuke Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Zikula / PostNuke.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# The PostNuke product is stopped and again started same  product with the name zikula.
# This script first searches the version of postnuke installed , if it not founds then
# it serches for the zikula installed.

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/postnuke", "/PostNuke", "/zikula", "/framework", "/Zikula_Core", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( res && "PostNuke" >< res && egrep( pattern:"<meta name=.generator. content=.PostNuke", string:res, icase:TRUE ) ) {

    version = "unknown";
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    ver_str = egrep( pattern:"<meta name=.generator. content=.PostNuke", string:res, icase:TRUE );
    ver_str = chomp( ver_str );
    ver = ereg_replace( pattern:".*content=.PostNuke ([0-9].*) .*", string:ver_str, replace:"\1" );
    if( ver == ver_str ) {

      url = dir + "/docs/manual.txt";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );

      if( 'PostNuke' >< res && egrep( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*$", string:res ) ) {
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        ver_str = egrep( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*$", string:res );
        ver_str = chomp( ver_str );
        ver = ereg_replace( pattern:".*PostNuke:.The (Phoenix|Platinum) Release.*\(([0-9].*)\)", string:ver_str, replace:"\2" );
        if( ver )
          version = ver;
      }
    }

    set_kb_item( name:"postnuke/detected", value:TRUE );
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:postnuke:postnuke:" );
    if( ! cpe )
      cpe = "cpe:/a:postnuke:postnuke";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"PostNuke",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver_str ),
                                              port:port );
    exit( 0 );
  }

  url = dir + "/docs/distribution/tour_page1.htm";
  req = http_get( item:url, port:port );
  res = http_keepalive_send_recv( port:port, data:req );
  res2 = http_get_cache( item:dir + "/index.php", port:port );
  res3 = http_get_cache( item:dir + "/", port:port );

  if( ( res =~ "^HTTP/1\.[01] 200" && ( "congratulations and welcome to Zikula" >< res || 'at <a href="http://community.zikula.org">community.zikula.org</a>.</p>' >< res ) ) ||
      ( res2 =~ "^HTTP/1\.[01] 200" && egrep( pattern:'(Powered by .*Zikula|a href="http://www\\.zikula\\.org">Zikula</a></p>)', string:res2 ) ) ||
      ( res3 =~ "^HTTP/1\.[01] 200" && egrep( pattern:'(Powered by .*Zikula|a href="http://www\\.zikula\\.org">Zikula</a></p>)', string:res3 ) ) ) {

    version = "unknown";

    ver = eregmatch( pattern:"welcome to Zikula ([0-9.]+)", string:res );
    if( ver[1] ) {
      version = ver[0];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    } else {
      url = dir + "/docs/CHANGELOG";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req );
      ver = eregmatch( pattern:"ZIKULA ([0-9.]+)", string:res, icase:FALSE );
      if( ver[1] ) {
        version = ver[1];
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"zikula/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:zikula:zikula_application_framework:" );
    if( ! cpe )
      cpe = "cpe:/a:zikula:zikula_application_framework";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Zikula",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );