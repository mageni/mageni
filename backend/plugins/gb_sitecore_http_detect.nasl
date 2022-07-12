# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108191");
  script_version("2021-11-12T06:52:57+0000");
  script_tag(name:"last_modification", value:"2021-11-12 11:32:18 +0000 (Fri, 12 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-10-16 15:54:00 +0200 (Mon, 16 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sitecore CMS/XP Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Sitecore CMS/XP.");

  script_xref(name:"URL", value:"https://www.sitecore.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", "/sitecore", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  res1 = http_get_cache( item:dir + "/login/", port:port, host:host );
  res2 = http_get_cache( item:dir + "/identity/login/shell/sitecoreidentityserver", port:port, host:host );
  res3 = http_get_cache( item:dir + "/shell/sitecore.version.xml", port:port, host:host );

  if( ( res1 =~ "Set-Cookie\s*:\s*SC_ANALYTICS_GLOBAL_COOKIE" ||
        res2 =~ "Set-Cookie\s*:\s*SC_ANALYTICS_GLOBAL_COOKIE" ) ||
        ( ( res1 =~ "[Ss]itecore" || res2 =~ "[Ss]itecore" ) &&
        ( res1 =~ '<img id="BannerLogo" src="[^"]*/login/logo\\.png" alt="Sitecore Logo"' ||
          res1 =~ '<form method="post" action="[^"]*/login' ||
          res1 =~ 'href="[^"]*/login/login\\.css"' ||
          "<title>Sitecore</title>" >< res2 ) ) ||
        "<company>Sitecore Corporation" >< res3 ) {

    version = "unknown";

    vers = eregmatch( pattern:"Sitecore version.*\(Sitecore ([0-9.]+)\)", string:res1 );
    if( isnull( vers[1] ) )
      vers = eregmatch( pattern:"Sitecore\.NET ([0-9.]+) \(rev\. ([0-9.]+) Hotfix ([0-9\-]+)\)", string:res1 );

    if( isnull( vers[1] ) )
      vers = eregmatch( pattern:"Sitecore\.NET ([0-9.]+) \(rev\. ([0-9.]+)\)", string:res1 );

    if( isnull( vers[1] ) )
      vers = eregmatch( pattern:"Sitecore\.NET ([0-9.]+)", string:res1 );

    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      concUrl = http_report_vuln_url(  port:port, url:dir + "/login/", url_only:TRUE );
    } else {
      url = "/sitecore/shell/sitecore.version.xml";
      res = http_get_cache( port:port, item:url, host:host );

      # <information>
      #  <version>
      #    <major>10</major>
      #    <minor>0</minor>
      #    <build>1</build>
      #    <revision>004842</revision>
      #  </version>
      #  <date>November 21, 2020</date>
      #  <title>Sitecore.NET</title>
      #  <company>Sitecore Corporation A/S.</company>
      vers = eregmatch( pattern:"<major>([0-9]+).*<minor>([0-9]+).*<build>([0-9]+)?.*<revision>([0-9]+)( Hotfix ([0-9-]+))?<", string:res );

      if( isnull( vers[1] ) ) {
        url = dir + "/shell/sitecore.version.xml";
        res = http_get_cache( port:port, item:url, host:host );

        vers = eregmatch( pattern:"<major>([0-9]+).*<minor>([0-9]+).*<build>([0-9]+)?.*<revision>([0-9]+)( Hotfix ([0-9-]+))?<", string:res );
      }

      if( ! isnull( vers[1] ) ) {
        version = vers[1] + "." + vers[2];
        if( ! isnull( vers[3] ) )
          version += "." + vers[3];
        concUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( ! isnull( vers[4] ) )
      extra += "Revision: " + vers[4];

    if( ! isnull( vers[6] ) )
      extra += '\nHotfix:   ' + vers[6];

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sitecore:cms:" );
    if( ! cpe )
      cpe = "cpe:/a:sitecore:cms";

    set_kb_item( name:"sitecore/cms/detected", value:TRUE );
    set_kb_item( name:"sitecore/cms/http/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Sitecore CMS/XP",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0],
                                              concludedUrl:concUrl,
                                              extra:extra ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );