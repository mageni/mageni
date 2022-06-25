###############################################################################
# OpenVAS Vulnerability Test
#
# SNMP OS Identification
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103429");
  script_version("2019-05-07T06:30:33+0000");
  script_tag(name:"last_modification", value:"2019-05-07 06:30:33 +0000 (Tue, 07 May 2019)");
  script_tag(name:"creation_date", value:"2012-02-17 10:17:12 +0100 (Fri, 17 Feb 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SNMP OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"This script performs SNMP sysDesc based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cisco_ios.inc");
include("snmp_func.inc");

SCRIPT_DESC = "SNMP OS Identification";
BANNER_TYPE = "SNMP SysDesc";

port    = get_snmp_port(default:161);
sysdesc = get_snmp_sysdesc(port:port);
if(!sysdesc)
  exit(0);

# Linux xy 3.16.0-4-amd64 #1 SMP Debian 3.16.36-1+deb8u2 (2016-10-19) x86_64
if( sysdesc =~ "Linux" && " Debian " >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  # nb: The order matters in case of backports which might have something like +deb9~bpo8
  if( "~bpo6" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 6.0" );
    register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
  } else if( "+deb7" >< sysdesc || "~bpo7" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 7" );
    register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb8" >< sysdesc || "~bpo8" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 8" );
    register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "+deb9" >< sysdesc || "~bpo9" >< sysdesc ) {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux 9" );
    register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    set_kb_item( name:"Host/OS/SNMP", value:"Debian GNU/Linux" );
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SINDOH MF 3300_2300 version NR.APS.N434 kernel 2.6.18.5 All-N-1
if( sysdesc =~ " kernel [0-9]\." ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Linux" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"kernel ([0-9]+\.[^ ]*).*", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'Linux', version:version[1], cpe:'cpe:/o:linux:kernel', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'Linux', cpe:'cpe:/o:linux:kernel', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Microsoft Corp. Windows 98.
# Hardware: x86 Family 15 Model 4 Stepping 1 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)
# Hardware: x86 Family 6 Model 8 Stepping 3 AT/AT COMPATIBLE - Software: Windows NT Version 4.0 (Build Number: 1381 Uniprocessor Free )
if( sysdesc =~ "Microsoft Corp. Windows 98" || sysdesc =~ "Hardware:.*Software: Windows" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Windows" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:75 );

  if( "windows 98" >< sysdesc ) {
    register_and_report_os( os:'Windows 98', cpe:'cpe:/o:microsoft:windows_98', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  version = eregmatch( pattern:"Software: Windows.*Version ([0-9.]+)", string:sysdesc );

  if( isnull( version[1] ) || version[1] !~ "[4-6]\.[0-2]" ) {
    register_and_report_os( os:'Windows', cpe:'cpe:/o:microsoft:windows', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  winVal = version[1];

  if( winVal == "4.0" ) {
    register_and_report_os( os:'Windows NT', version:"4.0", cpe:'cpe:/o:microsoft:windows_nt', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( ( winVal == "5.0" || winVal == "5.1") && ( "Windows 2000" >< sysdesc ) ) {
    register_and_report_os( os:'Windows 2000', cpe:'cpe:/o:microsoft:windows_2000', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "5.1" ) {
    register_and_report_os( os:'Windows XP', cpe:'cpe:/o:microsoft:windows_xp', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "5.2" ) {
    register_and_report_os( os:'Windows Server 2003', cpe:'cpe:/o:microsoft:windows_server_2003', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.0" ) {
    register_and_report_os( os:'Windows Vista', cpe:'cpe:/o:microsoft:windows_vista', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.1" ) {
    register_and_report_os( os:'Windows 7', cpe:'cpe:/o:microsoft:windows_7', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( winVal == "6.2" ) {
    register_and_report_os( os:'Windows 8', cpe:'cpe:/o:microsoft:windows_8', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  # we don't know the real windows version if we reached here. So just register windows.
  register_and_report_os( os:'Windows', cpe:'cpe:/o:microsoft:windows', banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# FreeBSD localhost.localdomain 4.11-RELEASE-p26 FreeBSD 4.11-RELEASE-p26 #12: S i386
# pfSense localhost.localdomain 2.4.1-RELEASE pfSense FreeBSD 11.1-RELEASE-p2 amd64
if( sysdesc =~ "(FreeBSD|pfSense).* FreeBSD" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"FreeBSD" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:".*FreeBSD ([0-9.]+[^ ]*).*", string:sysdesc );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'FreeBSD', version:version[1], cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'FreeBSD', cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# NetBSD localhost.localdomain 1.6.1_STABLE NetBSD 1.6.1_STABLE (SCZ_16) #0: Thu May 24 14:42:04 CEST 2007...
if( sysdesc =~ "NetBSD.* NetBSD" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"NetBSD" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:".*NetBSD ([0-9.]+[^ ]*).*", string:sysdesc );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'NetBSD', version:version[1], cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'NetBSD', cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Powered by OpenBSD
# OpenBSD localhost.localdomain 4.2 GENERIC#375 i386
if( sysdesc =~ "^OpenBSD" || sysdesc =~ "Powered by OpenBSD" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"OpenBSD" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"OpenBSD.* ([0-9.]+) GENERIC", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'OpenBSD', version:version[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'OpenBSD', cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit(0);
}

# HP-UX rx2600 B.11.23 U ia64 3979036319
if( sysdesc =~ "^HP-UX" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"HP UX" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"^HP-UX [^ ]* ([^ ]*)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'HP UX', version:version[1], cpe:"cpe:/o:hp:hp-ux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'HP UX', cpe:"cpe:/o:hp:hp-ux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SunOS NXSAM 5.10 Generic_127128-11 i86pc
# SunOS wlanapp 5.10 Generic_139555-08 sun4v
if( sysdesc =~ "^SunOS" ) {

  typ = " (sparc)";
  if( "i86pc" >< sysdesc ) {
    typ = " (i386)";
  }

  set_kb_item( name:"Host/OS/SNMP", value:"Sun Solaris" + typ );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"^SunOS .* (5\.[0-9]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'SunOS', version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'SunOS', cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# HP ETHERNET MULTI-ENVIRONMENT,ROM P.22.01,JETDIRECT,JD86,EEPROM P.24.07,CIDATE 12/13/2002
if( "JETDIRECT" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"HP JetDirect" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  register_and_report_os( os:'JetDirect', cpe:"cpe:/h:hp:jetdirect", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Cisco Internetwork Operating System Software  IOS (tm) GS Software (GSR-P-M), Version 12.0(21)ST7, EARLY DEPLOYMENT RELEASE SOFTWARE (fc1)  ...
# Cisco IOS Software, C3550 Software (C3550-IPSERVICESK9-M), Version 12.2(25)SEE2, RELEASE SOFTWARE (fc1)
if( ( sysdesc =~ "^Cisco IOS" || "IOS (tm)" >< sysdesc ) && ( "Cisco IOS XR" >!< sysdesc && "Cisco IOS XE" >!< sysdesc && "IOS-XE" >!< sysdesc ) ) {

  set_kb_item(name:"Host/OS/SNMP", value:"Cisco IOS");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch(pattern:"IOS.*Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*),", string:sysdesc);

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'IOS', version:version[1], cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
    set_kb_item( name:"cisco_ios/snmp/version", value:version[1] );
    set_kb_item( name:"cisco_ios/detected", value:TRUE );
  } else {
    register_and_report_os( os:'IOS', cpe:"cpe:/o:cisco:ios", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( ( sysdesc =~ "^Cisco IOS" || "IOS (tm)" >< sysdesc ) && "Cisco IOS XR" >!< sysdesc && ( "Cisco IOS XE" >< sysdesc || "IOS-XE" >< sysdesc ) ) {

  set_kb_item(name:"Host/OS/SNMP", value:"Cisco IOS XE");
  set_kb_item(name:"Host/OS/SNMP/Confidence", value:100);

  version = eregmatch( pattern:"IOS.*Version ([0-9]*\.[0-9]*\([0-9a-zA-Z]+\)[A-Z0-9.]*),", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    version[1] = iosver_2_iosxe_ver( iosver:version[1] );

    register_and_report_os( os:'IOS XE', version:version[1], cpe:"cpe:/o:cisco:ios_xe", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
    set_kb_item( name:"cisco_ios_xe/snmp/version", value:version[1] );
    set_kb_item( name:"cisco_ios_xe/detected", value:TRUE );
  } else {
    register_and_report_os( os:'IOS XE', cpe:"cpe:/o:cisco:ios_xe", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Base Operating System Runtime AIX version: 05.03.0000.0060
if( "Base Operating System Runtime AIX" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"AIX" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Base Operating System Runtime AIX version: ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'AIX', version:version[1], cpe:"cpe:/o:ibm:aix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'AIX', cpe:"cpe:/o:ibm:aix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Darwin localhost.localdomain 9.6.0 Darwin Kernel Version 9.6.0: Mon Nov 24 17:37:00 PST 2008; root:xnu-1228.9.59~1/RELEASE_I386 i386
if( "^Darwin " >< sysdesc || "Darwin Kernel" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Apple Mac OS X" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  register_and_report_os( os:'MAC OS X', cpe:"cpe:/o:apple:mac_os_x", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );

  exit( 0 );
}

# Juniper Networks, Inc. ex3200-24t internet router, kernel JUNOS 10.1R1.8 #0: 2010-02-12 17:24:20 UTC
if( "Juniper Networks" >< sysdesc && "JUNOS" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"JUNOS" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"JUNOS ([^ ]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'JunOS', version:version[1], cpe:"cpe:/o:juniper:junos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }  else {
    register_and_report_os( os:'JunOS', cpe:"cpe:/o:juniper:junos", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# localhost.localdomain AlphaServer 1200 5/533 4MB OpenVMS V7.3-1 Compaq TCP/IP Services for OpenVMS
if( "OpenVMS" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"OpenVMS" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"OpenVMS V([^ ]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'OpenVMS', version:version[1], cpe:"cpe:/o:hp:openvms", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'OpenVMS', cpe:"cpe:/o:hp:openvms", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Novell NetWare 5.70.08  October 3, 2008
if( "Novell NetWare" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Novell NetWare" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Novell NetWare ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'Netware', version:version[1], cpe:"cpe:/o:novell:netware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'Netware', cpe:"cpe:/o:novell:netware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Silicon Graphics Octane2 running IRIX64 version 6.5
# Silicon Graphics O2 running IRIX version 6.5
if( sysdesc =~ "running IRIX(64)? version" ) {

  set_kb_item( name:"Host/OS/SNMP", value:"IRIX" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"version ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'IRIX', version:version[1], cpe:"cpe:/o:sgi:irix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'IRIX', cpe:"cpe:/o:sgi:irix", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SCO OpenServer Release 6
if( "SCO OpenServer" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"SCO OpenServer" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"SCO OpenServer Release ([0-9]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'SCO', version:version[1], cpe:"cpe:/o:sco:openserver", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'SCO', cpe:"cpe:/o:sco:openserver", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# SCO UnixWare 7.1.4
if( "SCO UnixWare" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"SCO UnixWare" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"SCO UnixWare ([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'Unixware', version:version[1], cpe:"cpe:/o:sco:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'Unixware', cpe:"cpe:/o:sco:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Novell UnixWare v2.1
if( "Novell UnixWare" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Novell UnixWare" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Novell UnixWare v([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:'UnixWare', version:version[1], cpe:"cpe:/o:novell:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'UnixWare', cpe:"cpe:/o:novell:unixware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "ProSafe" >< sysdesc || "ProSAFE" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.108163 (gb_netgear_prosafe_snmp_detect.nasl)
}

if( "Cisco IOS XR" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.105079 (gb_cisco_ios_xr_detect_snmp.nasl)
}

if( "ArubaOS" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.105244 (gb_arubaos_detect.nasl)
}

if( "Cisco NX-OS" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.103799 (gb_cisco_nx_os_detect.nasl)
}

if( "Cisco Adaptive Security Appliance" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.106513 (gb_cisco_asa_version_snmp.nasl)
}

if( "Arista Networks EOS" >< sysdesc ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.106494 (gb_arista_eos_snmp_detect.nasl)
}

if( sysdesc =~ "^HyperIP" ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.108349 (gb_hyperip_snmp_detect.nasl)
}

if( "Siemens, SIMATIC HMI" >< sysdesc ) { # 1.3.6.1.4.1.25623.1.0.141682 (gb_simatic_hmi_snmp_detect.nasl)
  exit( 0 );
}

if( sysdesc =~ "^SMS [^ ]+ v?SMS" ) {
  exit( 0 ); # 1.3.6.1.4.1.25623.1.0.108569 (gb_tippingpoint_sms_snmp_detect.nasl)
}

# nb: More detailed OS Detection covered in gb_netapp_data_ontap_consolidation.nasl
if( sysdesc =~ "^NetApp Release " ) {
  register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "WatchGuard Fireware" >< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"WatchGuard Fireware" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"WatchGuard Fireware v([0-9.]+)", string:sysdesc );

  if( ! isnull( version[1] ) ) {
    register_product( cpe:"cpe:/o:watchguard:fireware:" + version[1] );
    register_and_report_os( os:'WatchGuard Fireware', version:version[1], cpe:"cpe:/o:watchguard:fireware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:'WatchGuard Fireware', cpe:"cpe:/o:watchguard:fireware", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( sysdesc =~ 'HP Comware (Platform )?Software' ) {
  register_and_report_os( os:'HP Comware OS', cpe:"cpe:/o:hp:comware_os", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Assume Linux/Unix for this device
if( "Triax TDX" >< sysdesc ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# e.g. IBM OS/400 V7R3M0
# IBM OS/400 V7R1M0
if( "IBM OS/400" >< sysdesc ) {
  version = eregmatch( pattern:"^IBM OS/400 ([^ ]+)", string:sysdesc );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"IBM OS/400", version:tolower( version[1] ), cpe:"cpe:/o:ibm:os_400", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"IBM OS/400", cpe:"cpe:/o:ibm:os_400", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

# Linux SOA1000 2.6.26.8 #62 SMP Mon Sep 21 18:13:37 CST 2009 i686 unknown
if( sysdesc =~ "Linux" && "Cisco IOS" >!< sysdesc ) {

  set_kb_item( name:"Host/OS/SNMP", value:"Linux" );
  set_kb_item( name:"Host/OS/SNMP/Confidence", value:100 );

  version = eregmatch( pattern:"Linux [^ ]* ([0-9]+\.[^ ]*).*", string:sysdesc );
  if( version[1] ) {

    # 2.0 SP2:
    # Linux hostname 3.10.0-327.59.59.37.h22.x86_64 #1 SMP Tue Sep 26 07:38:08 UTC 2017 x86_64
    # Unknown 2.0 release (SP5?)
    # Linux hostname 3.10.0-327.62.59.83.h163.x86_64 #1 SMP Wed Jan 16 06:10:00 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
    if( version[1] =~ "\.h[0-9]+" ) {
      register_and_report_os( os:"EulerOS", cpe:"cpe:/o:huawei:euleros", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    # Oracle Linux 7.4
    # Linux hostname 4.1.12-112.14.15.el7uek.x86_64 #2 SMP Thu Feb 8 09:58:19 PST 2018 x86_64 x86_64 x86_64 GNU/Linux
    if( ".el" >< version[1] && "uek." >< version[1] ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:version[1] );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Oracle Linux", version:version[1], cpe:"cpe:/o:oracle:linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Oracle Linux", cpe:"cpe:/o:oracle:linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }

    # e.g. CentOS 7.4 but also on RHEL
    # Linux hostname 3.10.0-693.el7.x86_64 #1 SMP Tue Aug 22 21:09:27 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    # nb: Keep below the Oracle Linux check above
    if( ".el" >< version[1] ) {
      version = eregmatch( pattern:"\.el([0-9]+)", string:version[1] );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Red Hat Enterprise Linux / CentOS", version:version[1], cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Red Hat Enterprise Linux / CentOS", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }

    # Fedora Core 24
    # Linux hostname 4.9.6-100.fc24.x86_64 #1 SMP Thu Jan 26 10:21:30 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
    if( ".fc" >< version[1] ) {
      version = eregmatch( pattern:"\.fc([0-9]+)", string:version[1] );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Fedora Core", version:version[1], cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }
  }

  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, proto:"udp", banner:sysdesc, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

register_unknown_os_banner( banner:sysdesc, banner_type_name:BANNER_TYPE, banner_type_short:"snmp_sysdesc_banner", port:port, proto:"udp" );

exit( 0 );