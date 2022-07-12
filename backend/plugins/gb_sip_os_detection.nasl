###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sip_os_detection.nasl 13746 2019-02-18 16:08:21Z cfischer $
#
# SIP Server OS Identification
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
  script_oid("1.3.6.1.4.1.25623.1.0.108201");
  script_version("$Revision: 13746 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-18 17:08:21 +0100 (Mon, 18 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-08-01 11:13:48 +0200 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SIP Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_dependencies("sip_detection.nasl");
  script_mandatory_keys("sip/detected");

  script_tag(name:"summary", value:"This script performs SIP banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("sip.inc");

SCRIPT_DESC = "SIP Server OS Identification";
BANNER_TYPE = "SIP server banner";

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port  = infos['port'];
proto = infos['proto'];

# nb: sip_get_banner is setting the full banner below banner if it has detected a SIP service.
# We just want to call it here so that this script can run "standalone".
sip_get_banner( port:port, proto:proto );
if( ! full_banner = get_kb_item( "sip/full_banner/" + proto + "/" + port ) )
  exit( 0 );

serverbanner = get_kb_item( "sip/server_banner/" + proto + "/" + port );
if( serverbanner )
  concluded = "Server Banner: " + serverbanner;

uabanner = get_kb_item( "sip/useragent_banner/" + proto + "/" + port );
if( uabanner ) {
  if( concluded )
    concluded += '\n';
  concluded = "User-Agent Banner: " + uabanner;
}

if( serverbanner ) {

  # Server: snom
  # nb: Older firmware versions had something like (see gb_snom_detect.nasl):
  # "Server: snom300/1.2.3
  # "Server: snom/1.2.3
  if( "snom" >< serverbanner ) {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  if( "+deb9" >< serverbanner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "+deb8" >< serverbanner ) {
    register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "~dfsg" >< serverbanner ) {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g. Server:Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0
  if( "Microsoft-Windows" >< serverbanner ) {
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  # e.g.
  # Server: kamailio (4.0.1 (sparc/solaris))
  # Server: kamailio (4.2.3 (x86_64/linux))
  # Server: Kamailio (1.5.4-notls (i386/linux))
  if( "kamailio" >< tolower( serverbanner ) ) {

    if( "/linux))" >< serverbanner ) {
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/solaris))" >< serverbanner ) {
      register_and_report_os( os:"Sun Solaris", cpe:"cpe:/o:sun:solaris", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/freebsd))" >< serverbanner ) {
      register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/openbsd))" >< serverbanner ) {
      register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }
  }
}

if( uabanner ) {

  # User-Agent: AVM FRITZ!Box Fon WLAN 7170 29.04.88 (Feb  9 2014)
  # User-Agent: FRITZ!OS
  if( "FRITZ!OS" >< uabanner || "AVM FRITZ" >< uabanner ) {
    register_and_report_os( os:"AVM FRITZ!OS", cpe:"cpe:/o:avm:fritz%21_os", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g. User-Agent: P3/v9.1.3.1590 QT/5.7.1 Xyclops/v2.7.5-r16845 OS/Windows 8 Network/Wi-Fi
  if( "OS/Windows" >< uabanner ) {
    if( "OS/Windows 7" >< uabanner ) {
      register_and_report_os( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "OS/Windows 8.1" >< uabanner ) {
      register_and_report_os( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "OS/Windows 8" >< uabanner ) {
      register_and_report_os( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else if( "OS/Windows 10" >< uabanner ) {
      register_and_report_os( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
    } else {
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"windows" );
      # nb: Also register an unknown banner so we can update the ones above
      register_unknown_os_banner( banner:uabanner, banner_type_name:BANNER_TYPE, banner_type_short:"sip_banner", port:port, proto:proto );
    }
    exit( 0 );
  }

  # e.g. User-Agent: Alcatel-Lucent 8460 ACS 12.0.2b0290
  # According to some docs the base OS is Red Hat but using Linux/Unix for now
  if( "Alcatel-Lucent" >< uabanner && "ACS" >< uabanner ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # e.g. User-Agent: (XMCDVUA v2.2.1b90q_pj22 System[Linux-3.10/armv7l] Make[QUANTA] Model[QTAQZ3] OS[5.1.1] InternetMode[WIFI] Ver[6.6.1] State[])
  if( "System[Linux" >< uabanner ) {
    version = eregmatch( pattern:"System\[Linux-([0-9.]+)", string:uabanner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  # User-Agent: IceWarp SIP 12.0.3.1 RHEL6 x64
  # User-Agent: IceWarp SIP 12.0.4.0 DEB8 x64
  # User-Agent: IceWarp SIP 12.0.2.1 x64
  # User-Agent: IceWarp SIP 12.0.3.1
  # User-Agent: IceWarp SIP 12.1.1.0 RC24 RHEL7 x64
  # User-Agent: IceWarp SIP 12.0.4.0 UBUNTU1404 x64
  # User-Agent: IceWarp SIP 12.1.2.0 (2018-05-03) RHEL6 x64
  if( "IceWarp SIP" >< uabanner ) {
    if( os_info = eregmatch( pattern:"User-Agent: IceWarp SIP ([0-9.]+) ([^ ]+) ([^ ]+)( [^ ]+)?", string:uabanner, icase:FALSE ) ) {
      if( max_index( os_info ) == 5 ) {
        offset = 1;
      } else {
        offset = 0;
      }
      if( "RHEL" >< os_info[2+offset] ) {
        version = eregmatch( pattern:"RHEL([0-9.]+)", string:os_info[2+offset] );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Red Hat Enterprise Linux", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      } else if( "DEB" >< os_info[2+offset] ) {
        version = eregmatch( pattern:"DEB([0-9.]+)", string:os_info[2+offset] );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      } else if( "UBUNTU" >< os_info[2+offset] ) {
        version = eregmatch( pattern:"UBUNTU([0-9.]+)", string:os_info[2+offset] );
        if( ! isnull( version[1] ) ) {
          version = ereg_replace( pattern:"^([0-9]{1,2})(04|10)$", string:version[1], replace:"\1.\2" );
          register_and_report_os( os:"Ubuntu", version:version, cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, proto:proto, banner:concluded, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
        exit( 0 );
      }
      # nb: No exit here as we want to report an unknown OS later...
    } else {
      exit( 0 ); # No OS info so just skip this IceWarp banner...
    }
  }
}

register_unknown_os_banner( banner:full_banner, banner_type_name:BANNER_TYPE, banner_type_short:"sip_banner", port:port, proto:proto );

exit( 0 );