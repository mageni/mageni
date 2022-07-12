###############################################################################
# OpenVAS Vulnerability Test
#
# Telnet OS Identification
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111069");
  script_version("2019-05-07T06:30:33+0000");
  script_tag(name:"last_modification", value:"2019-05-07 06:30:33 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2015-12-13 13:00:00 +0100 (Sun, 13 Dec 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Telnet OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/banner/available");

  script_tag(name:"summary", value:"This script performs Telnet banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

SCRIPT_DESC = "Telnet OS Identification";
BANNER_TYPE = "Telnet banner";

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( ! banner || banner == "" || isnull( banner ) )
  exit( 0 );

if( "Welcome to Microsoft Telnet Service" >< banner ||
    "Georgia SoftWorks Telnet Server for Windows" >< banner ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "Welcome to the Windows CE Telnet Service" >< banner || "Windows CE Telnet Service cannot accept anymore concurrent users" >< banner ) {
  register_and_report_os( os:"Microsoft Windows CE", cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "FreeBSD/" >< banner && ( "(tty" >< banner || "(pts" >< banner ) ) {
  register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "NetBSD/" >< banner && ( "(tty" >< banner || "(pts" >< banner ) ) {
  register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# UPS / USV on embedded OS
if( "ManageUPSnet" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Rittal CMC-TC-PU on an embedded linux, keep this above the login: check below as some devices doesn't show that login: prompt
if( "CMC-TC-PU2" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "User Access Verification" >< banner && "Username:" >< banner ) {
  register_and_report_os( os:"Cisco IOS", cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# There are plenty of services available which are responding / reporting
# a telnet banner even if those are no telnet services. Only continue with
# the reporting if we actually got a login/password prompt related to a
# Telnet service.
if( telnet_has_login_prompt( data:banner ) ) {

  if( "metasploitable login:" >< banner && "Warning: Never expose this VM to an untrusted network!" >< banner ) {
    register_and_report_os( os:"Ubuntu", version:"8.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "SunOS" >< banner && "login:" >< banner ) {
    version = eregmatch( pattern:"SunOS ([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  if( "VxWorks login:" >< banner || "Welcome to NetLinx" >< banner ) {
    register_and_report_os( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Debian GNU/Linux" >< banner ) {
    version = eregmatch( pattern:"Debian GNU/Linux ([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"Debian GNU/Linux", version:version[1], cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
        if( "lenny" >< banner ) {
          register_and_report_os( os:"Debian GNU/Linux", version:"5.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "squeeze" >< banner ) {
          register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
        } else if( "wheezy" >< banner ) {
          register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "jessie" >< banner ) {
          register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
    }
    exit( 0 );
  }

  if( "Ubuntu" >< banner ) {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "CentOS release" >< banner ) {
    register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Fedora release" >< banner ) {
    register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Fedora Core release" >< banner ) {
    register_and_report_os( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Red Hat Enterprise Linux" >< banner ) {
    version = eregmatch( pattern:"Red Hat Enterprise Linux (Server|ES|AS|Client) release ([0-9.]+)", string:banner );
    if( ! isnull( version[2] ) ) {
      register_and_report_os( os:"Red Hat Enterprise Linux " + version[1], version:version[2], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  if( "Red Hat Linux release" >< banner ) {
    register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "-gentoo-" >< banner ) {
    register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Welcome to SuSE Linux 6.4 (i386) - Kernel 2.4.17 (0).
  if( "Welcome to SUSE Linux" >< banner || "Welcome to SuSE Linux" >< banner ) {
    version = eregmatch( pattern:"Welcome to S[uU]SE Linux ([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"SUSE Linux", version:version[1], cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  if( "Welcome to openSUSE Leap" >< banner ) {
    version = eregmatch( pattern:"Welcome to openSUSE Leap ([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"openSUSE Leap", version:version[1], cpe:"cpe:/o:opensuse_project:leap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"openSUSE Leap", cpe:"cpe:/o:opensuse_project:leap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  if( "Welcome to openSUSE" >< banner ) {
    version = eregmatch( pattern:"Welcome to openSUSE ([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"openSUSE", version:version[1], cpe:"cpe:/o:novell:opensuse", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"openSUSE", cpe:"cpe:/o:novell:opensuse", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  # nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
  if( banner =~ '^\r\n\r\nData ONTAP' ) {
    register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Fabric OS" >< banner )
    exit( 0 ); # Covered by gb_brocade_fabricos_telnet_detect.nasl

  # Too generic, e.g.:
  # hostname login:
  # nb: Keep at the bottom so the others above are matching first.
  if( eregmatch( string:banner, pattern:'^\r\n[^ ]+ login: $', icase:FALSE ) )
    exit( 0 );

  # Seen on e.g. EulerOS. There might be others Distros using the same so we're ignoring this for now...
  #
  # Authorized users only. All activities may be monitored and reported.
  # hostname login:
  #
  if( eregmatch( string:banner, pattern:'^\r\nAuthorized users only\\. All activities may be monitored and reported\\.\r\n[^ ]+ login: $', icase:FALSE ) )
    exit( 0 );

  # Seen on e.g. NetApp Data ONTAP
  if( banner == '\r\nToo many users logged in!  Please try again later.\r\n' )
    exit( 0 );

  register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"telnet_banner", port:port );
}

exit( 0 );