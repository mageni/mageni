# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108342");
  script_version("2022-09-16T08:08:14+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-16 08:08:14 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"creation_date", value:"2018-02-17 15:43:37 +0100 (Sat, 17 Feb 2018)");
  script_name("Pi-hole Ad-Blocker Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://pi-hole.net/");

  script_tag(name:"summary", value:"HTTP based detection of the Pi-hole Ad-Blocker.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );

# nb:
# - "/admin/" is/was the default one in AdminLTE < 5.14
# - "/admin/login.php" is used since AdminLTE 5.14
# - a few have been seen on the top-level as well
# - Keep the /admin/ ones first as installs having the "/admin/" subfolder might be detected twice
#   otherwise because a few of the patterns below are matching as well (on purpose).
foreach url( make_list( "/admin/", "/admin/login.php", "/", "/login.php" ) ) {

  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" &&
      ( "<title>Pi-hole Admin Console</title>" >< buf || # nb: Only in older versions
        egrep( string:buf, pattern:"<title>Pi-hole - [^<]+</title>", icase:FALSE ) || # AdminLTE 5.3.1+ has <title>Pi-hole - $hostname</title>
        '<a href="http://pi-hole.net" class="logo"' >< buf ||
        '<script src="scripts/pi-hole/js/footer.js"></script>' >< buf ||
        "<!-- Pi-hole: A black hole for Internet advertisements" >< buf ||
        ( "Open Source Ad Blocker" >< buf && "<small>Designed For Raspberry Pi</small>" >< buf ) ) ) {

    install        = "/";
    pihole_version = "unknown";
    web_version    = "unknown";
    ftl_version    = "unknown";
    concludedUrl   = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"pi-hole/detected", value:TRUE );

    #<b>Pi-hole Version </b> v3.2.1
    # newer versions (5.1+) have:
    # <strong>Pi-hole</strong>
    # <a href="https://github.com/pi-hole/pi-hole/releases/v5.1.1" rel="noopener" target="_blank">v5.1.1</a>
    pihole_vers = eregmatch( string:buf, pattern:"(<b>Pi-hole Version ?</b> ?|<strong>Pi-hole</strong>[^>]+>)v([0-9.]+)" );
    if( pihole_vers[2] )
      pihole_version = pihole_vers[2];

    #<b>Web Interface Version </b>v3.2.1
    # newer versions (5.1+) have:
    # <strong>Web Interface</strong>
    # <a href="https://github.com/pi-hole/AdminLTE/releases/v5.1" rel="noopener" target="_blank">v5.1</a>
    web_vers = eregmatch( string:buf, pattern:"(<b>Web Interface Version ?</b> ?|<strong>Web Interface</strong>[^>]+>)v([0-9.]+)" );
    if( web_vers[2] )
      web_version = web_vers[2];

    #<b>FTL Version </b> vDev (v2.13.2, v2.13.2
    #<b>FTL Version </b> v3.0
    # newer versions (5.1+) have:
    # <strong>FTL</strong>
    # <a href="https://github.com/pi-hole/FTL/releases/v5.1" rel="noopener" target="_blank">v5.1</a>
    ftl_vers = eregmatch( string:buf, pattern:"(<b>FTL Version ?</b> ?(vDev \()?|<strong>FTL</strong>[^>]+>)v([0-9.]+)" );
    if( ftl_vers[3] )
      ftl_version = ftl_vers[3];

    pihole_cpe = build_cpe( value:pihole_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:pi-hole:" );
    if( ! pihole_cpe )
      pihole_cpe = "cpe:/a:pi-hole:pi-hole";

    web_cpe = build_cpe( value:web_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:web:" );
    if( ! web_cpe )
      web_cpe = "cpe:/a:pi-hole:web";

    ftl_cpe = build_cpe( value:ftl_version, exp:"^([0-9.]+)", base:"cpe:/a:pi-hole:ftl:" );
    if( ! ftl_cpe )
      ftl_cpe = "cpe:/a:pi-hole:ftl";

    register_product( cpe:pihole_cpe, location:install, port:port, service:"www" );
    register_product( cpe:web_cpe, location:install, port:port, service:"www" );
    register_product( cpe:ftl_cpe, location:install, port:port, service:"www" );

    # Runs only on Linux based OS like Debian, Ubuntu, Fedora etc.
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, desc:"Pi-hole Ad-Blocker Detection", runs_key:"unixoide" );

    report  = build_detection_report( app:"Pi-hole",
                                      version:pihole_version,
                                      install:install,
                                      cpe:pihole_cpe,
                                      concluded:pihole_vers[0],
                                      concludedUrl:concludedUrl );
    report += '\n\n';
    report += build_detection_report( app:"Pi-hole Web Interface",
                                      version:web_version,
                                      install:install,
                                      cpe:web_cpe,
                                      concluded:web_vers[0],
                                      concludedUrl:concludedUrl );
    report += '\n\n';
    report += build_detection_report( app:"Pi-hole FTL",
                                      version:ftl_version,
                                      install:install,
                                      cpe:ftl_cpe,
                                      concluded:ftl_vers[0],
                                      concludedUrl:concludedUrl );

    log_message( port:port, data:report );
    exit( 0 ); # nb: We only want to detect it once...
  }
}

exit( 0 );