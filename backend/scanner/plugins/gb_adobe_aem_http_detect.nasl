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
  script_oid("1.3.6.1.4.1.25623.1.0.807067");
  script_version("2021-06-29T14:46:54+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-06-30 10:34:52 +0000 (Wed, 30 Jun 2021)");
  script_tag(name:"creation_date", value:"2016-02-11 14:43:49 +0530 (Thu, 11 Feb 2016)");
  script_name("Adobe Experience Manager (AEM) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Adobe Experience Manager (AEM).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

detection_patterns = make_list(
  # <meta name="granite.login.imsLoginUrl" content=""><title>AEM Sign In</title>
  #     <title>AEM Sign In</title>
  "<title>AEM Sign In",
  # <h1 class="coral-Heading coral-Heading--1">Welcome to Adobe Experience Manager</h1>
  ">Welcome to Adobe Experience Manager<",
  # <div class="legal-footer"><span>C 2016 Adobe Systems Incorporated. All Rights Reserved.</span><ul id="usage-box">
  # <div class="legal-footer"><span>C 2019 Adobe. All Rights Reserved.</span><ul id="usage-box">
  # nb: The "C" in the two strings above is the copyright symbol.
  "[0-9]+ Adobe.+All Rights Reserved",
  # <link rel="stylesheet" href="/etc/clientlibs/granite/coralui2.min.css" type="text/css">
  # <script type="text/javascript" src="/etc/clientlibs/granite/jquery.min.js"></script>
  '(src|href)="/etc/clientlibs/granite/',
  # <img id="id-a1098d7987b99f147b887e1d2760ea41" src="/content/dam/somepath/someimage.svg" alt=""/>
  '(src|href)="/content/dam/',
  # <link rel="shortcut icon" href="/etc/designs/somepath/favicon.ico" type="image/x-icon"/>
  '(src|href)="/etc/designs/',
  # <script type="text/javascript" src="/etc.clientlibs/clientlibs/granite/jquery.min.1494c0abbe501301e2ab9daecc6082a8.js"></script>
  '(src|href)="/etc\\.clientlibs/clientlibs/granite/',
  # X-Adobe-Content: AEM
  # X-Adobe-Content: AEM-Offers
  # nb: icase:TRUE in the egrep is not used on purpose so that the "AEM" is checked in uppercase.
  "^[Xx]-[Aa]dobe-[Cc]ontent\s*:\s*AEM" );

host = http_host_name( dont_add_port:TRUE );

foreach url( make_list( "/libs/granite/core/content/login.html?", "/" ) ) {

  # nb: Overwriting this because each endpoint should be evaluated separately.
  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  res = http_get_cache( item:url, port:port );
  if( ( res && res =~ "^HTTP/1\.[01] 200" ) || banner =~ "X-Adobe-Content" ) {

    foreach pattern( detection_patterns ) {

      if( "[Xx]-[Aa]dobe-[Cc]ontent" >< pattern )
        concl = egrep( string:banner, pattern:pattern, icase:TRUE );
      else
        concl = egrep( string:res, pattern:pattern, icase:FALSE );

      if( concl ) {

        # nb: Limit the reporting to a single found item to keep the "concluded" string smaller
        concl = split( concl, keep:FALSE );
        concl = concl[0];

        if( concluded )
          concluded += '\n';

        # nb: Minor formatting change for the reporting.
        concl = chomp( concl );
        concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
        concluded += "    " + concl;

        # Existence of the banner is always counting as a successful detection.
        if( "[Xx]-[Aa]dobe-[Cc]ontent" >< pattern )
          found += 2;
        else
          found++;
      }
    }

    if( found > 1 ) {

      version = "unknown";
      install = "/";
      set_kb_item( name:"adobe/aem/detected", value:TRUE );
      set_kb_item( name:"adobe/aem/http/detected", value:TRUE );
      concludedUrl = '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

      foreach url( make_list( "/system/console", "/system/console/configMgr", "/system/console/bundles" ) ) {
        res = http_get_cache( item:url, port:port );
        if( res =~ "^HTTP/1\.[01] 401" && "OSGi Management Console" >< res ) {
          set_kb_item( name:"www/content/auth_required", value:TRUE );
          set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:url );
          extra = "The OSGi Management Console is reachable at: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
          break;
        }
      }

      url = "/system/sling/cqform/defaultlogin.html";
      res = http_get_cache( item:url, port:port );
      if( res =~ "^HTTP/1\.[01] 200" && "QUICKSTART_HOMEPAGE" >< res )
        extra += '\nThe Sling console is reachable at: ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

      url = "/crx/de/index.jsp";
      res = http_get_cache( item:url, port:port );
      if( res =~ "^HTTP/1\.[01] 200" && ( "<title>CRXDE Lite</title>" >< res || "icons/crxde_favicon.ico" >< res ) )
        extra += '\nThe CRXDE console is reachable at: ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

      cpe = "cpe:/a:adobe:experience_manager";
      register_product( cpe:cpe, location:install, port:port, service:"www" );

      log_message( data:build_detection_report( app:"Adobe Experience Manager",
                                                version:version,
                                                install:install,
                                                cpe:cpe,
                                                concluded:concluded,
                                                concludedUrl:concludedUrl,
                                                extra:extra ),
                                                port:port );

      exit( 0 );
    }
  }
}

exit( 0 );