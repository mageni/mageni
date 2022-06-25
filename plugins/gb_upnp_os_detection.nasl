###############################################################################
# OpenVAS Vulnerability Test
#
# UPnP Protocol OS Identification
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108200");
  script_version("2019-04-24T11:06:32+0000");
  script_tag(name:"last_modification", value:"2019-04-24 11:06:32 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("UPnP Protocol OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_upnp_detect.nasl");
  script_require_udp_ports("Services/udp/upnp", 1900);
  script_mandatory_keys("upnp/identified");

  script_tag(name:"summary", value:"This script performs UPnP protocol based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "UPnP Protocol OS Identification";
BANNER_TYPE = "UPnP protocol banner";

# Only covering UDP, the TCP banners are handled via sw_http_os_detection.nasl
port = get_kb_item( "Services/udp/upnp" );
if( ! port ) port = 1900;
if( ! get_udp_port_state( port ) ) exit( 0 );
if( ! banner = get_kb_item( "upnp/" + port + "/banner" ) ) exit( 0 );

if( "FRITZ!Box" >< banner ) {
  register_and_report_os( os:"AVM FRITZ!OS", cpe:"cpe:/o:avm:fritz%21_os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# SERVER: LINUX-2.6 UPnP/1.0 MiniUPnPd/1.5
# Server: Linux/2.4.22-1.2115.nptl UPnP/1.0 miniupnpd/1.0
if( egrep( pattern:"^SERVER: Linux", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"Server: Linux(/|\-)([0-9.x]+)", string:banner, icase:TRUE );
  if( ! isnull( version[2] ) ) {
    register_and_report_os( os:"Linux", version:version[2], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# nb: Keep the UPnP pattern in sync with sw_http_os_detection.nasl for the TCP counterpart...

# SERVER: Ubuntu/7.10 UPnP/1.0 miniupnpd/1.0
# Server: Ubuntu/10.10 UPnP/1.0 miniupnpd/1.0
# SERVER: Ubuntu/hardy UPnP/1.0 MiniUPnPd/1.2
# SERVER: Ubuntu/lucid UPnP/1.0 MiniUPnPd/1.4
# nb: It might be possible that some of the banners below doesn't exist
# on newer or older Ubuntu versions. Still keep them in here as we can't know...
if( egrep( pattern:"^SERVER: Ubuntu", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"SERVER: Ubuntu/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/warty" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"4.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/hoary" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"5.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/breezy" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"5.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/dapper" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"6.06", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/edgy" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"6.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/feisty" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"7.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/gutsy" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"7.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/hardy" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/intrepid" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"8.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/jaunty" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"9.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/karmic" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"9.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/lucid" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/maverick" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/natty" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/oneiric" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/precise" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/quantal" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/raring" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/saucy" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/trusty" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/utopic" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/vivid" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/wily" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/xenial" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/yakkety" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/zesty" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/artful" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"17.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/bionic" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"18.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/cosmic" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"18.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Ubuntu/disco" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"19.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
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
    register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/stretch" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/jessie" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/wheezy" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/squeeze" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/lenny" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/etch" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"4.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/sarge" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"3.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/woody" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"3.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/potato" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"2.2", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/slink" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"2.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/hamm" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"2.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/bo" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"1.3", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/rex" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"1.2", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "Debian/buzz" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"1.1", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Server: CentOS/5.6 UPnP/1.0 MiniUPnPd/1.6
# Server: CentOS/6.2 UPnP/1.0 miniupnpd/1.0
# Server: CentOS/5.5 UPnP/1.0 MiniUPnPd/1.6
if( egrep( pattern:"^Server: CentOS", string:banner, icase:TRUE ) ) {
  version = eregmatch( pattern:"Server: CentOS/([0-9.]+)", string:banner, icase:TRUE );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"CentOS", version:version[1], cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# TODO: There are more UPnP implementations reporting the OS:
# SERVER: FreeBSD/8.1-PRERELEASE UPnP/1.0 MiniUPnPd/1.4
# SERVER: FreeBSD/9 UPnP/1.0 MiniUPnPd/1.4
# Server: FreeBSD/8.0-RC1 UPnP/1.0 MiniUPnPd/1.2
# Server: SUSE LINUX/11.3 UPnP/1.0 miniupnpd/1.0
# Server: Fedora/8 UPnP/1.0 miniupnpd/1.0
# SERVER: Fedora/10 UPnP/1.0 MiniUPnPd/1.4

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"upnp_banner", port:port, proto:"udp" );

exit( 0 );