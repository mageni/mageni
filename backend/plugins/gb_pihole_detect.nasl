###############################################################################
# OpenVAS Vulnerability Test
#
# Pi-hole Ad-Blocker Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.108342");
  script_version("2019-05-25T14:34:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-25 14:34:10 +0000 (Sat, 25 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-17 15:43:37 +0100 (Sat, 17 Feb 2018)");
  script_name("Pi-hole Ad-Blocker Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://pi-hole.net/");

  script_tag(name:"summary", value:"Detection of the Pi-hole Ad-Blocker.

  The script sends a connection request to the server and attempts to
  identify an installed Pi-hole Ad-Blocker and various components from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

# nb: "/admin/" is the default but have seen a few on the top-level as well
foreach url( make_list( "/", "/admin/" ) ) {

  buf = http_get_cache( item:url, port:port );

  if( buf =~ "^HTTP/1\.[01] 200" &&
      ( "<title>Pi-hole Admin Console</title>" >< buf ||
        '<a href="http://pi-hole.net" class="logo"' >< buf ||
        '<script src="scripts/pi-hole/js/footer.js"></script>' >< buf ) ) {

    install        = "/";
    pihole_version = "unknown";
    web_version    = "unknown";
    ftl_version    = "unknown";
    concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"pi-hole/detected", value:TRUE );

    #<b>Pi-hole Version </b> v3.2.1
    pihole_vers = eregmatch( string:buf, pattern:"<b>Pi-hole Version </b> v([0-9.]+)" );
    if( pihole_vers[1] ) pihole_version = pihole_vers[1];

    #<b>Web Interface Version </b>v3.2.1
    web_vers = eregmatch( string:buf, pattern:"<b>Web Interface Version </b>v([0-9.]+)" );
    if( web_vers[1] ) web_version = web_vers[1];

    #<b>FTL Version </b> vDev (v2.13.2, v2.13.2
    #<b>FTL Version </b> v3.0
    ftl_vers = eregmatch( string:buf, pattern:"<b>FTL Version </b> (vDev \()?v([0-9.]+)" );
    if( ftl_vers[2] ) ftl_version = ftl_vers[2];

    # CPEs not registered yet
    pihole_cpe = build_cpe( value:pihole_version, exp:"^([0-9.]+)", base:"cpe:/a:pihole:pihole:" );
    if( isnull( pihole_cpe ) )
      pihole_cpe = "cpe:/a:pihole:pihole";

    web_cpe = build_cpe( value:web_version, exp:"^([0-9.]+)", base:"cpe:/a:pihole:web:" );
    if( isnull( web_cpe ) )
      web_cpe = "cpe:/a:pihole:web";

    ftl_cpe = build_cpe( value:ftl_version, exp:"^([0-9.]+)", base:"cpe:/a:pihole:ftl:" );
    if( isnull( ftl_cpe ) )
      ftl_cpe = "cpe:/a:pihole:ftl";

    register_product( cpe:pihole_cpe, location:install, port:port );
    register_product( cpe:web_cpe, location:install, port:port );
    register_product( cpe:ftl_cpe, location:install, port:port );

    # Runs only on Linux based OS like Debian, Ubuntu, Fedora etc.
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, desc:"Pi-hole Ad-Blocker Detection", runs_key:"unixoide" );

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
  }
}

exit( 0 );