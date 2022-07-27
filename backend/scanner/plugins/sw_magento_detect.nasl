###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_magento_detect.nasl 11276 2018-09-07 08:18:40Z cfischer $
#
# Magento Shop Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Updated to differentiate Enterprise and Community Edition on 28-01-2016:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105227");
  script_version("2019-03-29T12:36:57+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-29 12:36:57 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2015-02-09 12:00:00 +0100 (Mon, 09 Feb 2015)");
  script_name("Magento Shop Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of the installation path and version
  of a Magento Shop.

  The script sends HTTP GET requests and try to comfirm the Magento Shop installation
  path and version from the responses.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/magento", "/shop", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;
  install = dir;
  if( dir == "/" ) dir = "";
  flag = FALSE;
  outdatedChangelog = FALSE;
  CE = FALSE;
  EE = FALSE;

  url1 = dir + "/admin/";
  res1 = http_get_cache( item:url1, port:port );

  url2 = dir + "/";
  res2 = http_get_cache( item:url2, port:port );

  url3 = dir + "/RELEASE_NOTES.txt";
  res3 = http_get_cache( item:url3, port:port );

  url4 = dir + "/downloader/";
  res4 = http_get_cache( item:url4, port:port );

  if( res1 && "Magento Inc." >< res1 || res2 && ("/skin/frontend/" >< res2 || "text/x-magento-init" >< res2) ||
      res3 && "=== Improvements ===" >< res3 || res4 && "Magento Connect Manager ver." >< res4 ) {

    version = "unknown";
    if( dir == "" ) rootInstalled = TRUE;

    ver = eregmatch( pattern:"==== ([0-9\.]+) ====", string:res3 );

    #nb: The RELEASE_NOTES.txt is not updated between version 1.7.0.2 and 1.9.1.0
    if( ver[1] && ( version_is_less_equal( version:ver[1], test_version:"1.7.0.2" ) &&
        "NOTE: Current Release Notes are maintained at:" >!< res3 ) ||
        version_is_greater_equal( version:ver[1], test_version:"1.9.1.0" )) {
      conclUrl = report_vuln_url( port:port, url:url3, url_only:TRUE );
      version  = ver[1];
      flag     = TRUE;
      if( "NOTE: Current Release Notes are maintained at:" >< res3 )
        outdatedChangelog = TRUE;
    }

    if( ! flag )  {
      ver = eregmatch( pattern:"Magento Connect Manager ver. ([0-9\.]+)", string:res4 );
      if( ver[1] && version_is_less_equal( version:ver[1], test_version:"1.7.0.2" ) && ! outdatedChangelog ) {
        conclUrl = report_vuln_url( port:port, url:url4, url_only:TRUE );
        version  = ver[1];
      }
    }

    #nb: First try to read from Release Notes
    if( res3 && "magento" >< res3 && "=== Improvements ===" >< res3 ) {
      if( res3 =~ "(c|C)ommunity_(e|E)dition" ) {
        CE    = TRUE;
        extra = '\nEdition gathered from:\n' + report_vuln_url( port:port, url:url3, url_only:TRUE );
      }
      else if( res3 =~ "(e|E)nterprise (E|e)dition" ) {
        EE    = TRUE;
        extra = '\nEdition gathered from:\n' + report_vuln_url( port:port, url:url3, url_only:TRUE );
      }
    }

    #nb: License opens up on accessing URL: /css/styles.css
    if( ! EE || ! CE )  {
      #nb: URL for Enterprise Edition
      url5 = dir + "/errors/enterprise/css/styles.css";
      req  = http_get( item:url5, port:port );
      res5 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( res5 && res5 =~ "(M|m)agento (E|e)nterprise (E|e)dition" && res5 =~ "license.*enterprise.edition" ) {
        EE    = TRUE;
        extra = '\nEdition gathered from:\n' + report_vuln_url( port:port, url:url5, url_only:TRUE );
      } else {
        #nb: URL for Community Edition
        url6 = dir + "/errors/default/css/styles.css";
        req  = http_get( item:url6, port:port );
        res6 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( res6 && res6 =~ "(M|m)agento" && res6 =~ "license.*opensource.*Free" ) {
          CE    = TRUE;
          extra = '\nEdition gathered from:\n' + report_vuln_url( port:port, url:url6, url_only:TRUE );
        }
      }
    }

    if( CE ) {
      set_kb_item( name:"magento/CE/installed", value:TRUE );
      app = "Magento Community Edition";
    } else if( EE ) {
      set_kb_item( name:"magento/EE/installed", value:TRUE );
      app = "Magento Enterprise Edition";
    } else {
      app = "Magento Unknown Edition";
    }

    set_kb_item( name:"www/" + port + "/magento", value:version );
    set_kb_item( name:"magento/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9a-z.]+)", base:"cpe:/a:magentocommerce:magento:" );
    if( isnull( cpe ) || version == "unknown" )
      cpe = "cpe:/a:magentocommerce:magento";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:app,
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
