###############################################################################
# OpenVAS Vulnerability Test
#
# HTTP OS Identification
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (C) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111067");
  script_version("2019-05-07T06:30:33+0000");
  script_tag(name:"last_modification", value:"2019-05-07 06:30:33 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-10 16:00:00 +0100 (Thu, 10 Dec 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTTP OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl",
                      "sw_apcu_info.nasl", "gb_phpinfo_output_detect.nasl"); # nb: Both are setting a possible existing banner used by check_php_banner()
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based OS detection from the HTTP/PHP
  banner or default test pages.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

SCRIPT_DESC = "HTTP OS Identification";

function check_http_banner( port, banner ) {

  local_var port, banner, banner_type, version;

  if( banner && banner = egrep( pattern:"^Server:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    # Bea/Oracle WebLogic is cross-platform
    if( "Server: WebLogic" >< banner )
      return;

    # WIBU Systems CodeMeter Web Admin is cross-platform
    if( "WIBU-SYSTEMS HTTP Server" >< banner )
      return;

    # Apache Spark is cross-platform
    if( banner == "Server: Spark" )
      return;

    # Lotus Domino is cross-platform
    if( banner == "Server: Lotus-Domino" ||
        banner == "Server: Lotus Domino" ) return;

    # BigIP Load Balancer on the frontend, registering this could report/use a wrong OS for the backend server
    if( banner == "Server: BigIP" ) return;

    # aMule Server is cross-patform
    if( banner == "Server: aMule" ) return;

    # Transmission Server is cross-platform
    if( banner == "Server: Transmission" ) return;

    # Logitech Media Server is cross-platform
    if( banner == "Server: Logitech Media Server" ||
        egrep( pattern:"^Server: Logitech Media Server \([0-9.]+\)$", string:banner ) ||
        egrep( pattern:"^Server: Logitech Media Server \([0-9.]+ - [0-9.]+)$", string:banner ) )
      return;

    # NZBGet is cross-platform
    if( "Server: nzbget" >< banner ) return;

    # API TCP listener is cross-platform
    if( "Server: Icinga" >< banner ) return;

    # Runs on Windows, Linux and Mac OS X
    if( "Kerio Connect" >< banner || "Kerio MailServer" >< banner ) return;

    # Server: SentinelProtectionServer/7.3
    # Server: SentinelKeysServer/1.3.2
    # Seems to be running on Windows and NetWare systems.
    if( "SentinelProtectionServer" >< banner || "SentinelKeysServer" >< banner ) return;

    # Server: EWS-NIC5/15.18
    # Server: EWS-NIC5/96.55
    # Running on different printers from e.g. Xerox, Dell or Epson. The OS is undefined so just return...
    if( egrep( pattern:"^Server: EWS-NIC5/[0-9.]+$", string:banner ) ) return;

    # Server: CTCFC/1.0
    # Commtouch Anti-Spam Daemon (ctasd.bin) running on Windows and Linux (e.g. IceWarp Suite)
    if( egrep( pattern:"^Server: CTCFC/[0-9.]+$", string:banner ) ) return;

    # e.g. Server: SimpleHTTP/0.6 Python/2.7.5 -> Python is cross-platform
    if( egrep( pattern:"^Server: SimpleHTTP/[0-9.]+ Python/[0-9.]+$", string:banner ) ) return;

    # e.g. Server: MX4J-HTTPD/1.0 -> Java implementation, cross-patform
    if( egrep( pattern:"^Server: MX4J-HTTPD/[0-9.]+$", string:banner ) ) return;

    # e.g. Server: libwebsockets or server: libwebsockets
    if( egrep( pattern:"^Server: libwebsockets$", string:banner, icase:TRUE ) ) return;

    # e.g. Server: mt-daapd/svn-1696 or Server: mt-daapd/0.2.4.1
    # Cross-Platform
    if( egrep( pattern:"^Server: mt-daapd/?([0-9.]+|svn-[0-9]+)?$", string:banner, icase:TRUE ) ) return;

    # e.g. Server: Mongoose/6.3 or Server: Mongoose
    # Cross-Platform
    if( egrep( pattern:"^Server: Mongoose/?[0-9.]*$", string:banner, icase:TRUE ) ) return;

    if( banner == "Server:" ||
        banner == "Server: " ||
        banner == "Server: Undefined" || # Unknown
        banner == "Server: WebServer" || # e.g. D-Link DIR- devices
        banner == "Server: squid" ||
        banner == "Server: nginx" ||
        banner == "Server: Apache" ||
        banner == "Server: lighttpd" ||
        banner == "Server: sfcHttpd" ||
        banner == "Server: Web" || # Seen on TrendMicro TippingPoint Security Management System (SMS) but might exist on other products as well...
        banner == "Server: Allegro-Software-RomPager" || # Vendor: "Works with any OS vendor and will function without an OS if needed"
        banner == "Server: Apache-Coyote/1.0" ||
        banner == "Server: Apache-Coyote/1.1" ||
        banner == "Server: HASP LM" || # Is running under windows and linux
        banner == "Server: Mbedthis-Appweb" || # Is running under various OS variants
        banner == "Server: Embedthis-Appweb" || # Is running under various OS variants
        banner == "Server: Embedthis-http" || # Is running under various OS variants
        banner == "Server: GoAhead-Webs" || # Is running under various OS variants
        banner == "Server: Mojolicious (Perl)" || # Cross-platform
        banner == "Server: Java/0.0" || # Cross-platform, running on e.g. VIBNODE devices
        banner == "Server: NessusWWW" || # Nessus could be running on Windows, Linux/Unix or MacOS
        banner == "Server: Embedded Web Server" ||
        banner == "Server: EZproxy" || # runs on Linux or Windows
        banner == "Server: com.novell.zenworks.httpserver" || # Cross-platform
        "erver: BBC " >< banner || # OV Communication Broker runs on various different OS variants
        "Server: PanWeb Server/" >< banner || # Already covered by gb_palo_alto_webgui_detect.nasl
        egrep( pattern:"^Server: com.novell.zenworks.httpserver/[0-9.]+$", string:banner ) || # Cross-platform, e.g. Server: com.novell.zenworks.httpserver/1.0
        egrep( pattern:"^Server: DHost/[0-9.]+ HttpStk/[0-9.]+$", string:banner ) || # DHost/9.0 HttpStk/1.0 from Novell / NetIQ eDirectory, runs on various OS variants
        egrep( pattern:"^Server: Tomcat/[0-9.]+$", string:banner ) || # Quite outdated Tomcat, e.g. Server: Tomcat/2.1
        egrep( pattern:"^Server: Themis [0-9.]+$", string:banner ) || # Currently unknown
        egrep( pattern:"^Server: Mordac/[0-9.]+$", string:banner ) || # Currently unknown
        egrep( pattern:"^Server: eHTTP v[0-9.]+$", string:banner ) || # Currently unknown, have seen this on HP ProCurves but also on some login pages without any info
        egrep( pattern:"^Server: Agranat-EmWeb/[0-9_R]+$" ) || # Currently unknown, might be an Alcatel device...
        egrep( pattern:"^Server: gSOAP/[0-9.]+$", string:banner ) || # Cross-platform
        egrep( pattern:"^Server: squid/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^Server: squid/[0-9.]+\.STABLE[0-9.]+$", string:banner ) || # e.g. Server: squid/2.7.STABLE5
        egrep( pattern:"^Server: Jetty\([0-9.v]+\)$", string:banner ) || # e.g. Server: Jetty(7.3.1.v20110307)
        egrep( pattern:"^Server: nginx/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^Server: Apache/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^Server: lighttpd/[0-9.]+$", string:banner ) ||
        egrep( pattern:"^Server: CompaqHTTPServer/[0-9.]+$", string:banner ) || # HP SMH, cross-platform, e.g. Server: CompaqHTTPServer/2.1
        egrep( pattern:"^Server: http server [0-9.]+$", string:banner ) || # e.g. Server: http server 1.0
        egrep( pattern:"^Server: Web Server [0-9.]+$", string:banner ) || # e.g. Server: Web Server 1.1
        egrep( pattern:"^Server: MiniServ/[0-9.]+$", string:banner ) || # From Webmin/Usermin, cross-platform,  e.g. Server: MiniServ/1.550
        egrep( pattern:"^Server: RealVNC/[0-9.]+$", string:banner ) || # Cross-platform, e.g. Server: RealVNC/4.0
        egrep( pattern:"^Server: HASP LM/[0-9.]+$", string:banner ) || # Is running under windows and linux
        egrep( pattern:"^Server: Mbedthis-Appweb/[0-9.]+$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^Server: Embedthis-http/[0-9.]+$", string:banner ) || # Is running under various OS variants, banner e.g. Server: Embedthis-http/4.0.0
        egrep( pattern:"^Server: Embedthis-Appweb/[0-9.]+$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^Server: GoAhead-Webs/[0-9.]+$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^Server: Allegro-Software-RomPager/[0-9.]+$", string:banner ) || # Vendor: "Works with any OS vendor and will function without an OS if needed"
        egrep( pattern:"^Server: CompaqHTTPServer/[0-9.]+ HPE System Management Homepage$", string:banner ) || # Is running under various OS variants
        egrep( pattern:"^Server: CompaqHTTPServer/[0-9.]+ HP System Management Homepage/[0-9.]+$", string:banner ) || # e.g. Server: CompaqHTTPServer/9.9 HP System Management Homepage/2.1.2.127, is running under various OS variants
        egrep( pattern:"^Server: Payara Server +[0-9.]+ #badassfish$", string:banner ) ) { # Cross-platform, e.g. Server: Payara Server  4.1.2.172 #badassfish
      return;
    }

    # Seen on e.g. EulerOS. There might be others Distros using the same so we're ignoring this for now...
    # Server: Apache/2.4.6 () mod_auth_gssapi/1.3.1 mod_nss/1.0.14 NSS/3.28.4 mod_wsgi/3.4 Python/2.7.5
    if( egrep( pattern:"^Server: Apache/[0-9.]+ \(\)(( (mod_auth_gssapi|mod_nss|NSS|mod_wsgi|Python)/[0-9.]+)*)?$", string:banner, icase:TRUE ) )
      return;

    banner_type = "HTTP Server banner";

    # nb: Keep the UPnP pattern in sync with gb_upnp_os_detection.nasl for the UDP counterpart...

    # SERVER: Ubuntu/7.10 UPnP/1.0 miniupnpd/1.0
    # Server: Ubuntu/10.10 UPnP/1.0 miniupnpd/1.0
    # SERVER: Ubuntu/hardy UPnP/1.0 MiniUPnPd/1.2
    # SERVER: Ubuntu/lucid UPnP/1.0 MiniUPnPd/1.4
    # nb: It might be possible that some of the banners below doesn't exist
    # on newer or older Ubuntu versions. Still keep them in here as we can't know...
    if( egrep( pattern:"^SERVER: Ubuntu", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"SERVER: Ubuntu/([0-9.]+)", string:banner, icase:TRUE );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/warty" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/hoary" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/breezy" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/dapper" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/edgy" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/feisty" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/gutsy" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/hardy" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/intrepid" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/jaunty" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/karmic" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/lucid" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/maverick" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/natty" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/oneiric" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/precise" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/quantal" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/raring" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/saucy" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/trusty" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/utopic" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/vivid" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/wily" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/xenial" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/yakkety" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/zesty" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/artful" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/bionic" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/cosmic" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Ubuntu/disco" >< banner ) {
        register_and_report_os( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # Server: Debian/5.0.10 UPnP/1.0 MiniUPnPd/1.6
    # Server: Debian/4.0 UPnP/1.0 miniupnpd/1.0
    # Server: Debian/squeeze/sid UPnP/1.0 miniupnpd/1.0
    # SERVER: Debian/wheezy/sid UPnP/1.0 MiniUPnPd/1.2
    # Server: Debian/wheezy/sid UPnP/1.0 MiniUPnPd/1.6
    # SERVER: Debian/lenny UPnP/1.0 MiniUPnPd/1.2
    # nb: It might be possible that some of the banners below doesn't exist
    # on newer or older Debian versions. Still keep them in here as we can't know...
    if( egrep( pattern:"^Server: Debian", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"Server: Debian/([0-9.]+)", string:banner, icase:TRUE );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/stretch" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/jessie" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/wheezy" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/squeeze" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/lenny" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/etch" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/sarge" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/woody" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/potato" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/slink" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"2.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/hamm" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"2.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/bo" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"1.3", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/rex" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"1.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Debian/buzz" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"1.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # Server: CentOS/5.6 UPnP/1.0 MiniUPnPd/1.6
    # Server: CentOS/6.2 UPnP/1.0 miniupnpd/1.0
    # Server: CentOS/5.5 UPnP/1.0 MiniUPnPd/1.6
    if( egrep( pattern:"^Server: CentOS", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"Server: CentOS/([0-9.]+)", string:banner, icase:TRUE );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"CentOS", version:version[1], cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # TODO: There are more UPnP implementations reporting the OS:
    # SERVER: FreeBSD/8.1-PRERELEASE UPnP/1.0 MiniUPnPd/1.4
    # SERVER: FreeBSD/9 UPnP/1.0 MiniUPnPd/1.4
    # Server: FreeBSD/8.0-RC1 UPnP/1.0 MiniUPnPd/1.2
    # Server: SUSE LINUX/11.3 UPnP/1.0 miniupnpd/1.0
    # Server: Fedora/8 UPnP/1.0 miniupnpd/1.0
    # SERVER: Fedora/10 UPnP/1.0 MiniUPnPd/1.4

    # Server: MS .NET Remoting, MS .NET CLR 4.0.30319.42000
    if( "MS .NET Remoting" >< banner || "MS .NET CLR" >< banner ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # Server: cisco-IOS
    if( "Server: cisco-IOS" >< banner ) {
      register_and_report_os( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Runs only on Unix/Linux/BSD
    # e.g. Server: GoTTY/0.0.12
    # Server: Boa/0.94.14rc21
    if( "Server: GoTTY" >< banner || "Server: Boa" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # "Mathopd is a very small, yet very fast HTTP server for UN*X systems."
    # e.g. Server: Mathopd/1.5p6
    if( "Server: Mathopd" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Microsoft-WinCE" >< banner ) {
      # e.g. Server: Microsoft-WinCE/5.0
      version = eregmatch( pattern:"Microsoft-WinCE/([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Microsoft Windows CE", version:version[1], cpe:"cpe:/o:microsoft:windows_ce", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      } else {
        register_and_report_os( os:"Microsoft Windows CE", cpe:"cpe:/o:microsoft:windows_ce", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      }
      return;
    }

    # Server: Jetty/4.2.x (VxWorks/WIND version 2.9 ppc java/1.1-rr-std-b12)
    if( "(VxWorks/" >< banner ) {
      register_and_report_os( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # TrentMicro OfficeScan Client runs only on Windows
    if( "Server: OfficeScan Client" >< banner ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    if( banner == "Server: CPWS" ) {
      register_and_report_os( os:"Check Point Gaia", cpe:"cpe:/o:checkpoint:gaia_os", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Embedded Linux
    if( "MoxaHttp" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "NetApp" >< banner ) {
      # Server: NetApp/7.3.7
      # Server: NetApp//8.2.3P3
      version = eregmatch( pattern:"NetApp//?([0-9a-zA-Z.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"NetApp Data ONTAP", version:version[1], cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # UPS / USV on embedded OS
    if( "ManageUPSnet Web Server" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Examples:
    # Server: Jetty/5.1.10 (Windows Server 2008/6.1 amd64 java/1.6.0_07
    # Server: Jetty/3.1.8 (Windows 7 6.1 x86)
    # Server: Jetty/5.1.10 (Windows Server 2008 R2/6.1 amd64 java/1.6.0_31
    # Server: Jetty/5.1.15 (Linux/2.6.27.45-crl i386 java/1.5.0
    if( "Jetty/" >< banner ) {
      if( "(Windows" >< banner ) {
        if( "(Windows Server 2016" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 10" >< banner ) {
          register_and_report_os( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2012 R2" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 8.1" >< banner ) {
          register_and_report_os( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2012" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 8" >< banner ) {
          register_and_report_os( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2008 R2" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 7" >< banner ) {
          register_and_report_os( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2008" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Vista" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows Server 2003" >< banner || "(Windows 2003" >< banner ) {
          register_and_report_os( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows XP" >< banner ) {
          register_and_report_os( os:"Microsoft Windows XP Professional", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( "(Windows 2000" >< banner ) {
          register_and_report_os( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }

        # Currently unknown but definitely not Windows NT:
        # Server: Jetty/5.1.4 (Windows NT (unknown)/6.2 x86 java/1.5.0_22
        # Server: Jetty/5.1.x (Windows NT (unknown)/10.0 amd64 java/1.8.0_121

        register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        # nb: We also want to report an unknown OS if none of the above patterns for Windows is matching
        register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
        return;
      }
      if( "(Linux" >< banner ) {
        version = eregmatch( pattern:"\(Linux/([0-9.]+)", string:banner );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }
    }

    if( "HPE-iLO-Server" >< banner || "HP-iLO-Server" >< banner ) {
      register_and_report_os( os:"HP iLO", cpe:"cpe:/o:hp:integrated_lights-out", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "AirTunes" >< banner ) {
      register_and_report_os( os:"Apple TV", cpe:"cpe:/o:apple:tv", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Cisco Secure Access Control Server
    if( banner =~ "ACS [0-9.]+" ) {
      register_and_report_os( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Microsoft-HTTPAPI" >< banner || ( "Apache" >< banner && ( "(Win32)" >< banner || "(Win64)" >< banner ) ) ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # MS Lync
    if( egrep( pattern:"^Server: RTC/[56]\.0", string:banner ) ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    # https://en.wikipedia.org/wiki/Internet_Information_Services#History
    # Some IIS versions are shipped with two OS variants so registering both here.
    # IMPORTANT: Before registering both make sure that both OS variants have reached EOL
    # as we currently can't control / prioritize which of the registered OS is chosen for
    # the "BestOS" we would e.g. report a Server 2012 as EOL if Windows 8 was chosen.
    if( "Microsoft-IIS" >< banner ) {
      version = eregmatch( pattern:"Microsoft-IIS/([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        if( version[1] == "10.0" ) {
          # keep: register_and_report_os( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          # keep: register_and_report_os( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          register_and_report_os( os:"Microsoft Windows Server 2016 or Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "8.5" ) {
          # keep: register_and_report_os( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          # keep: register_and_report_os( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          register_and_report_os( os:"Microsoft Windows Server 2012 R2 or Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "8.0" ) {
          # keep: register_and_report_os( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          # keep: register_and_report_os( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          register_and_report_os( os:"Microsoft Windows Server 2012 or Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "7.5" ) {
          # keep: register_and_report_os( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          # keep: register_and_report_os( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          register_and_report_os( os:"Microsoft Windows Server 2008 R2 or Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "7.0" ) {
          # keep: register_and_report_os( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          # keep: register_and_report_os( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          register_and_report_os( os:"Microsoft Windows Server 2008 or Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "6.0" ) {
          register_and_report_os( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          register_and_report_os( os:"Microsoft Windows XP Professional x64", cpe:"cpe:/o:microsoft:windows_xp:-:-:x64", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "5.1" ) {
          register_and_report_os( os:"Microsoft Windows XP Professional", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "5.0" ) {
          register_and_report_os( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "4.0" ) {
          register_and_report_os( os:"Microsoft Windows NT 4.0 Option Pack", cpe:"cpe:/o:microsoft:windows_nt:4.0", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "3.0" ) {
          register_and_report_os( os:"Microsoft Windows NT 4.0 SP2", cpe:"cpe:/o:microsoft:windows_nt:4.0:sp2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "2.0" ) {
          register_and_report_os( os:"Microsoft Windows NT 4.0", cpe:"cpe:/o:microsoft:windows_nt:4.0", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
        if( version[1] == "1.0" ) {
          register_and_report_os( os:"Microsoft Windows NT 3.51", cpe:"cpe:/o:microsoft:windows_nt:3.51", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
          return;
        }
      }
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      # nb: We also want to report an unknown OS if none of the above patterns for Windows is matching
      register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
      return;
    }

    if( "Apache" >< banner || "nginx" >< banner || "lighttpd" >< banner ) {

      if( "(SunOS," >< banner || "(SunOS)" >< banner ) {
        register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "/NetBSD" >< banner ) {
        register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(FreeBSD)" >< banner || "-freebsd-" >< banner  ) {
        register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "OpenBSD" >< banner ) {
        register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # http://archive.debian.org/debian/pool/main/a/apache2/
      # http://archive.debian.org/debian/pool/main/a/apache/
      # http://ftp.debian.org/debian/pool/main/a/apache2/
      if( "Apache/1.3.9 (Unix) Debian/GNU" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/1.3.26 (Unix) Debian GNU/Linux" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/1.3.33 (Debian GNU/Linux)" >< banner || "Apache/2.0.54 (Debian GNU/Linux)" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # Server: Apache/1.3.34 Ben-SSL/1.55 (Debian) PHP/4.4.4-8+etch6 mod_jk/1.2.18
      if( "Apache/1.3.34 (Debian)" >< banner || "Apache/2.2.3 (Debian)" >< banner || ( "Apache/1.3.34 Ben-SSL" >< banner && "(Debian)" >< banner ) ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.2.9 (Debian)" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.2.16 (Debian)" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.2.22 (Debian)" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.10 (Debian)" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "Apache/2.4.25 (Debian)" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(Debian)" >< banner || "(Debian GNU/Linux)" >< banner || "devel-debian" >< banner || "~dotdeb+" >< banner || "(Raspbian)" >< banner ) {
        # Apache/2.2.3 (Debian) mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-8+etch16 mod_perl/2.0.2 Perl/v5.8.8
        if( "PHP" >< banner && "+etch" >< banner ) {
          register_and_report_os( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }

      if( "(Gentoo)" >< banner || "-gentoo" >< banner ) {
        register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(Linux/SUSE)"  >< banner || "/SuSE)" >< banner ) {
        register_and_report_os( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(CentOS)" >< banner ) {
        if( "Apache/2.4.6 (CentOS)" >< banner ) { # http://mirror.centos.org/centos/7/os/x86_64/Packages/
          register_and_report_os( os:"CentOS", version:"7", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "Apache/2.2.15 (CentOS)" >< banner ) { # http://mirror.centos.org/centos/6/os/x86_64/Packages/
          register_and_report_os( os:"CentOS", version:"6", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "Apache/2.2.3 (CentOS)" >< banner ) { # http://vault.centos.org/5.0/os/x86_64/CentOS/
          register_and_report_os( os:"CentOS", version:"5", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "Apache/2.0.52 (CentOS)" >< banner ) { # http://vault.centos.org/4.0/os/x86_64/CentOS/RPMS/
          register_and_report_os( os:"CentOS", version:"4", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "Apache/2.0.46 (CentOS)" >< banner ) { # http://vault.centos.org/3.9/os/x86_64/RedHat/RPMS/
          register_and_report_os( os:"CentOS", version:"3", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }

      # TODO: Check and add banners of all Ubuntu versions. Take care of versions which
      # exists between multiple Ubuntu releases and register only the highest Ubuntu version.
      #
      # nb: Keep the PHP/ banner in sync with the one of check_php_banner()
      if( "(Ubuntu)" >< banner || ( "PHP/" >< banner && "ubuntu" >< banner ) ) {
        # Server: Apache/2.4.38 (Ubuntu) PHP/7.2.17-0ubuntu0.19.04.1
        if( "Apache/2.4.38 (Ubuntu)" >< banner || "ubuntu0.19.04" >< banner || "nginx/1.15.9 (Ubuntu)" >< banner ) {
          register_and_report_os( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "Apache/2.4.34 (Ubuntu)" >< banner || "PHP/7.2.10-0ubuntu1" >< banner || "nginx/1.15.5 (Ubuntu)" >< banner ) {
          register_and_report_os( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "Apache/2.4.29 (Ubuntu)" >< banner || "PHP/7.2.3-1ubuntu1" >< banner || "nginx/1.14.0 (Ubuntu)" >< banner ) {
          register_and_report_os( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "nginx/1.12.1 (Ubuntu)" >< banner ) {
          register_and_report_os( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "nginx/1.10.3 (Ubuntu)" >< banner ) {
          register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "nginx/1.4.6 (Ubuntu)" >< banner ) {
          register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }

      if( "(Red Hat Enterprise Linux)" >< banner ) {
        register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(Red Hat)" >< banner || "(Red-Hat/Linux)" >< banner ) {
        # nb: Doubled space is expected...
        if( "Apache/1.3.23 (Unix)  (Red-Hat/Linux)" >< banner ) {
          # http://vault.centos.org/2.1/source/i386/SRPMS/ -> apache-1.3.23-10.src.rpm
          # TODO: Redhat version currently unknown, CentOS release taken from the src rpm above.
          register_and_report_os( os:"CentOS", version:"2", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        return;
      }

      if( "(Fedora)" >< banner ) {
        register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(Oracle)" >< banner ) {
        register_and_report_os( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(Unix)" >< banner ) {
        register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "mini-http" >< banner && "(unix)" >< banner ) {
        register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( "(Univention)" >< banner ) {
        register_and_report_os( os:"Univention Corporate Server", cpe:"cpe:/o:univention:univention_corporate_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # Server: Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.1mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
      # Server: Apache-AdvancedExtranetServer/2.0.53 (Mandrakelinux/PREFORK-9mdk) mod_ssl/2.0.53 OpenSSL/0.9.7e PHP/4.3.10 mod_perl/1.999.21 Perl/v5.8.6
      if( banner =~ "\(Mandrake ?[Ll]inux" ) {
        register_and_report_os( os:"Mandrake", cpe:"cpe:/o:mandrakesoft:mandrake_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }
    }

    if( "Nginx on Linux Debian" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # e.g.
    # ZNC 1.6.5+deb1 - http://znc.in
    # ZNC 1.6.5+deb1~bpo8 - http://znc.in
    # ZNC 1.6.5+deb1+deb9u1 - http://znc.in
    # nb: The +deb banner (which is using something like +deb1~bpo8) often doesn't match directly to the OS
    if( "ZNC" >< banner && ( "~bpo" >< banner || "+deb" >< banner ) ) {
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      if( "~bpo7" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "~bpo8" >< banner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "~bpo9" >< banner || banner =~ "\+deb[0-9]\+deb9" ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    if( "Nginx centOS" >< banner ) {
      register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "Nginx (OpenBSD)" >< banner || ( "Lighttpd" >< banner && "OpenBSD" >< banner ) ) {
      register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Proxmox VE is only running on unix-like OS
    if( egrep( pattern:"^Server: pve-api-daemon/[0-9.]+", string:banner, icase:TRUE ) ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # SERVER: POSIX, UPnP/1.0, Intel MicroStack/1.0.2126
    # Server: POSIX, UPnP/1.0, Intel MicroStack/1.0.2777
    if( "server: posix, upnp/1.0, intel microstack" >< tolower( banner ) ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Runs only on Unix-like OS. Keep down below to catch more detailed OS infos above first.
    # e.g. Server: nginx + Phusion Passenger 5.1.12
    # Server: nginx/1.8.1 + Phusion Passenger 5.0.27
    # Server: Apache/2.4.18 (Ubuntu) OpenSSL/1.0.2g SVN/1.9.3 Phusion_Passenger/5.0.27 mod_perl/2.0.9 Perl/v5.22.1
    if( banner =~ "^Server: .* Phusion[ _]Passenger" ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Server: IceWarp WebSrv/3.1
    # Server: IceWarp/11.4.6.0 RHEL7 x64
    # Server: IceWarp/11.4.6.0 UBUNTU1404 x64
    # Server: IceWarp/11.4.5.0 x64
    if( "Server: IceWarp" >< banner ) {
      if( os_info = eregmatch( pattern:"Server: IceWarp( WebSrv)?/([0-9.]+) ([^ ]+) ([^ ]+)", string:banner, icase:FALSE ) ) {
        if( "RHEL" >< os_info[3] ) {
          version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[3] );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          return;
        } else if( "DEB" >< os_info[3] ) {
          version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[3] );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          return;
        } else if( "UBUNTU" >< os_info[3] ) {
          version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[3] );
          if( ! isnull( version[1] ) ) {
            version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
            register_and_report_os( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
          return;
        }
        # nb: No return at this level here as we want to report an unknown OS later...
      } else {
        return; # No OS info so just skip this IceWarp banner...
      }
    }

    # CUPS is running only on MacOS and other UNIX-like operating systems
    if( "Server: CUPS/" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

      # Some CUPS deployments servers might provide additional OS pattern, report an unknown OS as well
      # if none of the generic known pattern below is matching...
      if( ! egrep( pattern:"^Server: CUPS/[0-9.]+ IPP/[0-9.]+$", string:banner ) &&
          ! egrep( pattern:"^Server: CUPS/[0-9.]+$", string:banner ) ) {
        register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
      }
      return;
    }

    # PowerDNS webserver is only running on Unix-like OS variants
    # https://doc.powerdns.com/md/authoritative/settings/#webserver
    # https://doc.powerdns.com/md/httpapi/README/
    # e.g. Server: PowerDNS/4.0.3
    if( "Server: PowerDNS" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      if( egrep( pattern:"^Server: PowerDNS/([0-9.]+)$", string:banner ) ) {
        # nb: Only return if there are no additional info within the banner so
        # that we're reporting an unknown OS later in other cases...
        return;
      }
    }

    # Tinyproxy is only running on Unix-like OS variants
    # https://tinyproxy.github.io/
    # e.g. Server: tinyproxy/1.8.4
    if( "Server: tinyproxy" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      if( egrep( pattern:"^Server: tinyproxy/([0-9.]+)$", string:banner ) ) {
        # nb: Only return if there are no additional info within the banner so
        # that we're reporting an unknown OS later in other cases...
        return;
      }
    }

    # nb: Keep at the bottom to catch all the more detailed patterns above...
    # Server: Compal Broadband Networks, Inc/Linux/2.6.39.3 UPnP/1.1 MiniUPnPd/1.7
    # SERVER: Linux/3.0.8, UPnP/1.0, Portable SDK for UPnP devices/1.6.6
    # SERVER: LINUX-2.6 UPnP/1.0 MiniUPnPd/1.5
    # Server: Linux, WEBACCESS/1.0, DIR-850L Ver 1.10WW
    if( egrep( pattern:"^Server: .*Linux", string:banner, icase:TRUE ) ) {
      version = eregmatch( pattern:"Server: .*Linux(/|\-)([0-9.x]+)", string:banner, icase:TRUE );
      if( ! isnull( version[2] ) ) {
        register_and_report_os( os:"Linux", version:version[2], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # e.g.:
    # Server: Apache/2.0.63FTF (NETWARE) mod_jk/1.2.23 PHP/5.0.5
    # Server: Apache/2.0.59 (NETWARE) mod_jk/1.2.21
    # Server: NetWare HTTP Stack
    if( banner =~ "Server: (NetWare HTTP Stack|Apache.+\(NETWARE\))" ) {
      register_and_report_os( os:"Novell NetWare / Open Enterprise Server (OES)", cpe:"cpe:/a:novell:open_enterprise_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
    if( egrep( pattern:"^Server: (NetApp|Data ONTAP)", string:banner, icase:FALSE ) ) {
      register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
  }
  return;
}

function check_php_banner( port, host ) {

  local_var port, host, phpList, phpFiles, phpBanner, phpscriptsUrls, phpscriptsUrl, _phpBanner, banner_type;

  phpList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
  if( phpList ) phpFiles = make_list( phpList );

  if( phpFiles[0] ) {
    phpBanner = get_http_banner( port:port, file:phpFiles[0] );
  } else {
    phpBanner = get_http_banner( port:port, file:"/index.php" );
  }

  phpBanner = egrep( pattern:"^X-Powered-By: PHP/.+$", string:phpBanner, icase:TRUE );
  if( ! phpBanner ) {
    # nb: Currently set by sw_apcu_info.nasl and gb_phpinfo_output_detect.nasl but could be extended by other PHP scripts providing such info
    phpscriptsUrls = get_kb_list( "php/banner/from_scripts/" + host + "/" + port + "/urls" );
    if( phpscriptsUrls && is_array( phpscriptsUrls ) ) {
      foreach phpscriptsUrl( phpscriptsUrls ) {
        _phpBanner = get_kb_item( "php/banner/from_scripts/" + host + "/" + port + "/full_versions/" + phpscriptsUrl );
        if( _phpBanner && _phpBanner =~ "[0-9.]+" ) {
          banner_type = "phpinfo()/ACP(u) output";
          phpBanner = _phpBanner;
          break; # TBD: Don't stop after the first hit? But that could report the very same PHP version if multiple scripts where found.
        }
      }
    }
  } else {
    banner_type = "PHP Server banner";
    phpBanner = chomp( phpBanner );
    if( egrep( pattern:"^X-Powered-By: PHP/[0-9.]+$", string:phpBanner ) ) return;
  }

  if( phpBanner ) {

    # nb: The naming of the sury.org PHP banners have some special syntax like: PHP/7.1.7-1+0~20170711133844.5+jessie~1.gbp5284f4
    # Using it separately as this still a too common pattern
    if( ".gbp" >< phpBanner ) {
      if( "+squeeze" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      } else if( "+wheezy" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      } else if( "+jessie" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      } else if( "+stretch" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }
    }

    # e.g. X-Powered-By: PHP/5.4.24-1+sury.org~lucid+1 or X-Powered-By: PHP/7.1.8-2+ubuntu14.04.1+deb.sury.org+4
    if( "sury.org" >< phpBanner ) {
      version = eregmatch( pattern:"\+ubuntu([0-9.]+)", string:phpBanner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }
    }

    # nb: It might be possible that some of the banners below doesn't exist
    # on newer or older Ubuntu versions. Still keep them in here as we can't know...
    if( "~warty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~hoary" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~breezy" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~dapper" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~edgy" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~feisty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~gutsy" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~hardy" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~intrepid" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~jaunty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~karmic" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~lucid" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~maverick" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~natty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~oneiric" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~precise" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~quantal" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~raring" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~saucy" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~trusty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~utopic" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~vivid" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~wily" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~xenial" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~yakkety" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~zesty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~artful" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~bionic" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~cosmic" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    } else if( "~disco" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # X-Powered-By: PHP/7.2.3-1ubuntu1
    #
    # nb: Newer PHP versions on Ubuntu doesn't use a "expose_php = On" but still trying to detect it here...
    #
    # TODO: Check and add banners of all Ubuntu versions. Take care of versions which
    # exists between multiple Ubuntu releases and register only the highest Ubuntu version.
    #
    # nb: Keep in sync with the PHP banner in check_http_banner()
    if( "ubuntu" >< phpBanner ) {
      # X-Powered-By: PHP/7.2.17-0ubuntu0.19.04.1
      if( "ubuntu0.19.04" >< phpBanner ) {
        register_and_report_os( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/7.2.10-0ubuntu1" >< phpBanner ) {
        register_and_report_os( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "PHP/7.2.3-1ubuntu1" >< phpBanner ) {
        register_and_report_os( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }

    # Apache/2.2.3 (Debian) mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-8+etch16 mod_perl/2.0.2 Perl/v5.8.8
    if( "+etch" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    if( "+deb" >< phpBanner || "~dotdeb+" >< phpBanner || "~deb" >< phpBanner || "~bpo" >< phpBanner ) {

      # nb: The order matters in case of backports which might have something like +deb9~bpo8
      if( "+deb6" >< phpBanner || "~deb6" >< phpBanner || "~dotdeb+squeeze" >< phpBanner || "~bpo6" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
      } else if( "+deb7" >< phpBanner || "~dotdeb+7" >< phpBanner || "~bpo7" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "+deb8" >< phpBanner || "~dotdeb+8" >< phpBanner || "~bpo8" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "+deb9" >< phpBanner ) {
        register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      return;
    }
    register_unknown_os_banner( banner:phpBanner, banner_type_name:banner_type, banner_type_short:"php_banner", port:port );
  }
  return;
}

function check_default_page( port ) {

  local_var port, buf, banner_type, check;

  buf = http_get_cache( item:"/", port:port );
  if( buf && ( buf =~ "^HTTP/1\.[01] 200" || buf =~ "^HTTP/1\.[01] 403" ) ) { # nb: Seems Oracle Linux is throwing a "forbidden" by default

    banner_type = "HTTP Server default page";

    if( "<title>Test Page for the Apache HTTP Server" >< buf ||
        "<title>Apache HTTP Server Test Page" >< buf ||
        "<title>Test Page for the Nginx HTTP Server" >< buf ) {

      check = "on Red Hat Enterprise Linux</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "powered by CentOS</title>";

      if( check >< buf ) {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on CentOS</title>";

      if( check >< buf ) {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Fedora Core</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Fedora</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "powered by Ubuntu</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "powered by Debian</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Mageia</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Mageia", cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on EPEL</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Scientific Linux</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Scientific Linux", cpe:"cpe:/o:scientificlinux:scientificlinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on the Amazon Linux AMI</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on CloudLinux</title>";

      if( check >< buf ) {
        register_and_report_os( os:"CloudLinux", cpe:"cpe:/o:cloudlinux:cloudlinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on SLES Expanded Support Platform</title>";

      if( check >< buf ) {
        register_and_report_os( os:"SUSE Linux Enterprise Server", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on EulerOS Linux</title>";

      if( check >< buf ) {
        register_and_report_os( os:"EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Oracle Linux</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      # Seen on e.g. Oracle Linux 7.4
      check = "powered by Linux</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<title>(Test Page for the (Apache|Nginx) HTTP Server|Apache HTTP Server Test Page) (powered by|on).*</title>" ) ) {
        register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( "<TITLE>Welcome to Jetty" >< buf ) {

      check = "on Debian</TITLE>";

      if( check >< buf ) {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<TITLE>Welcome to Jetty.*on.*</TITLE>" ) ) {
        register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( "<title>Welcome to nginx" >< buf ) {

      check = "on Debian!</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Ubuntu!</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Fedora!</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "on Slackware!</title>";

      if( check >< buf ) {
        register_and_report_os( os:"Slackware", cpe:"cpe:/o:slackware:slackware_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<title>Welcome to nginx on.*!</title>" ) ) {
        register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    if( "<title>Apache2" >< buf && "Default Page: It works</title>" >< buf ) {

      check = "<title>Apache2 Debian Default Page";

      if( check >< buf ) {
        register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "<title>Apache2 Ubuntu Default Page";

      if( check >< buf ) {
        register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      check = "<title>Apache2 centos Default Page";

      if( check >< buf ) {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
        return;
      }

      if( check = eregmatch( string:buf, pattern:"<title>Apache2 .* Default Page: It works</title>" ) ) {
        register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
      }
      return;
    }

    # CUPS is running only on MacOS and other UNIX-like operating systems
    if( check = eregmatch( string:buf, pattern:"<TITLE>(Forbidden|Home|Not Found|Bad Request) - CUPS.*</TITLE>", icase:TRUE ) ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check[0], desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
  }

  # TODO: There might be more of such default pages for other Distros...
  # But at least Ubuntu is using the index.nginx-debian.html as well.
  url = "/index.nginx-debian.html";
  buf = http_get_cache( item:url, port:port );
  if( buf && buf =~ "^HTTP/1\.[01] 200" && "<title>Welcome to nginx!</title>" >< buf ) {
    register_and_report_os( os:"Debian GNU/Linux or Ubuntu", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:report_vuln_url( port:port, url:url, url_only:TRUE ), desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  return;
}

function check_x_powered_by_banner( port, banner ) {

  local_var port, banner, banner_type;

  if( banner && banner = egrep( pattern:"^X-Powered-By:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    if( banner == "X-Powered-By:" || banner == "X-Powered-By: " ) return;

    # Both covered by check_php_banner()
    if( " PHP" >< banner ) return;
    # e.g. X-Powered-By: PHP/7.0.19 or X-Powered-By: PHP/7.0.19-1
    if( egrep( pattern:"^X-Powered-By: PHP/[0-9.]+(-[0-9]+)?$", string:banner, icase:TRUE ) ) return;

    # Express Framework is supported on Windows, Linux/Unix etc.
    if( banner == "X-Powered-By: Express" ) return;

    banner_type = "X-Powered-By Server banner";

    if( "PleskWin" >< banner || "ASP.NET" >< banner ) {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      return;
    }

    if( "PleskLin" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }

    # Runs only on Unix-like OS.
    # e.g. X-Powered-By: Phusion Passenger Enterprise 5.1.12
    # X-Powered-By: Phusion Passenger 5.0.27
    if( "Phusion Passenger" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
    register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_x_powered_by_banner", port:port );
  }
  return;
}

function check_user_agent_banner( port, banner ) {

  local_var port, banner, banner_type;

  if( banner && banner = egrep( pattern:"^User-Agent:.*$", string:banner, icase:TRUE ) ) {

    banner = chomp( banner );

    if( banner == "User-Agent:" || banner == "User-Agent: " ) return;

    # nb: If our user agent is echoed back to us just ignore it...
    if( http_get_user_agent() >< banner ) return;

    banner_type = "HTTP User Agent banner";

    # LibreOffice Online WebSocket server: https://github.com/LibreOffice/online/blob/master/wsd/README
    # This is the only service i have seen so far which is responding with a User-Agent: header
    # nb: loolwsd is only running on Linux/Unix
    if( "LOOLWSD WOPI Agent" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      return;
    }
    register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_user_agent_banner", port:port );
  }
  return;
}

port   = get_http_port( default:80 );
banner = get_http_banner( port:port );
host   = http_host_name( dont_add_port:TRUE );

# nb: The order matters here, e.g. we might have a "Server: Apache (Debian)" banner but a more detailed Debian Release in the PHP banner
check_php_banner( port:port, host:host );
check_http_banner( port:port, banner:banner );
check_default_page( port:port );
check_x_powered_by_banner( port:port, banner:banner );
check_user_agent_banner( port:port, banner:banner );

exit( 0 );
