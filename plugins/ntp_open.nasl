###############################################################################
# OpenVAS Vulnerability Test
#
# NTP read variables
#
# Authors:
# David Lodge
# Changes by rd:
# - recv() only receives the first two bytes of data (instead of 1024)
# - replaced ord(result[0]) == 0x1E by ord(result[0]) & 0x1E (binary AND)
#
# Copyright:
# Copyright (C) 2005 David Lodge
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10884");
  script_version("2019-05-27T07:13:17+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-27 07:13:17 +0000 (Mon, 27 May 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("NTP read variables");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Lodge");
  script_family("Product detection");
  script_require_udp_ports(123);

  script_tag(name:"summary", value:"This script performs detection of NTP servers.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");
include("misc_func.inc");

SCRIPT_DESC = "NTP read variables";

function ntp_read_list() {

  local_var data, soc, r, p;

  data = raw_string( 0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00 );
  soc = open_sock_udp( port );
  if( ! soc )
    return( NULL );

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( ! r )
    return( NULL );

  p = strstr( r, "version=" );
  if( ! p )
    p = strstr( r, "processor=" );

  if( ! p )
    p = strstr( r, "system=" );

  p = ereg_replace( string:p, pattern:raw_string(0x22), replace:"'" );

  if( p )
    return( p );

  return( NULL );
}

function ntp_installed() {

  local_var data, soc, r;

  data = raw_string( 0xDB, 0x00, 0x04, 0xFA, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                     0xBE, 0x78, 0x2F, 0x1D, 0x19, 0xBA, 0x00, 0x00 );

  soc = open_sock_udp( port );
  if( ! soc )
    return( NULL );

  send( socket:soc, data:data );
  r = recv( socket:soc, length:4096 );
  close( soc );

  if( strlen( r ) > 10 )
    return( r );

  return( NULL );
}

port = 123;
proto = "udp";
banner_type = "NTP banner";

if( ! get_udp_port_state( port ) )
  exit( 0 );

r = ntp_installed();

if( r ) {
  set_kb_item( name:"NTP/Running", value:TRUE );
  register_service( port:port, proto:"ntp", ipproto:proto );
  list = ntp_read_list();
  if( ! list ) {
    log_message( port:port, protocol:proto );
  } else {
    if( "system" >< list ) {
      s = egrep( pattern:"system=", string:list );
      os = ereg_replace( string:s, pattern:".*system='?([^',]+)[',].*", replace:"\1" );
      set_kb_item( name:"Host/OS/ntp", value:os );

      if( "linux" >< tolower( os ) ) {
        if( "-gentoo" >< os ) {
          register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else if( "-amazon" >< tolower( os ) ) {
          register_and_report_os( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {

          # Linux/2.6.35em1-g9733209
          # Linux2.4.20_mvl31-bcm95836cpci
          # Linux2.2.13
          version = eregmatch( pattern:"Linux/?([0-9.]+)", string:os );
          if( ! isnull( version[1] ) ) {
            register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
          } else {
            register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
          }
        }
      } else if( "windows" >< tolower( os ) ) {
        register_and_report_os( os:os, cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"windows" );
      } else if( "unix" >< tolower( os ) ) {
        register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "freebsd" >< tolower( os ) ) {

        # FreeBSDJNPR-11.0-20180730.2cd3a6e_buil
        # FreeBSDJNPR-10.3-20170422.348838_build
        # FreeBSD/10.1-RELEASE-p25
        # FreeBSD/11.2-RELEASE-p6
        version = eregmatch( pattern:"FreeBSD(/|JNPR-)([0-9.a-zA-Z\-]+)", string:os );
        if( ! isnull( version[2] ) ) {
          register_and_report_os( os:"FreeBSD", version:version[2], cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else if( "netbsd" >< tolower( os ) ) {
        version = eregmatch( pattern:"NetBSD/([0-9.a-zA-Z\-]+)", string:os );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"NetBSD", version:version[1], cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else if( "openbsd" >< tolower( os ) ) {
        version = eregmatch( pattern:"OpenBSD/([0-9.a-zA-Z\-]+)", string:os );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"OpenBSD", version:version[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else if( "sunos" >< tolower( os ) ) {
        version = eregmatch( pattern:"SunOS/([0-9.a-zA-Z\-]+)", string:os );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else if( "hp-ux" >< tolower( os ) ) {
        version = eregmatch( pattern:"HP-UX/([0-9.a-zA-Z\-]+)", string:os );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"HP-UX", version:version[1], cpe:"cpe:/o:hp:hp-ux", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"HP-UX", cpe:"cpe:/o:hp:hp-ux", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else if( "data ontap" >< tolower( os ) ) {

        # Data ONTAP/8.2.4P1
        # Data ONTAP/8.2.5
        # Data ONTAP/9.4P1
        version = eregmatch( pattern:"Data ONTAP/([0-9.a-zA-Z\-]+)", string:os );
        if( ! isnull( version[1] ) ) {
          register_and_report_os( os:"NetApp Data ONTAP", version:version[1], cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        } else {
          register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        }
      } else {
        # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
        register_and_report_os( os:os, banner_type:banner_type, banner:s, port:port, proto:proto, desc:SCRIPT_DESC, runs_key:"unixoide" );
        register_unknown_os_banner( banner:s, banner_type_name:banner_type, banner_type_short:"ntp_banner", port:port, proto:proto );
      }
    }

    if( "processor" >< list ) {
      s = egrep( pattern:"processor=", string:list );
      os = ereg_replace( string:s, pattern:".*processor='?([^',]+)[',].*", replace:"\1" );
      set_kb_item( name:"Host/processor/ntp", value:os );
    }

    if( "ntpd" >< list ) {
      set_kb_item( name:"NTP/Installed", value:TRUE );
      ntpVerFull = eregmatch( pattern:"version='([^']+)',", string:list );
      if( ! isnull( ntpVerFull[1] ) )
        set_kb_item( name:"NTP/Linux/FullVer", value:ntpVerFull[1] );

      ntpVer = eregmatch( pattern:"ntpd ([0-9.]+)([a-z][0-9]+)?-?(RC[0-9]+)?", string:list );

      if( ! isnull( ntpVer[1] ) ) {

        if( ntpVer[2] =~ "[a-z][0-9]+" && ntpVer[3] =~ "RC" ) {
          ntpVer = ntpVer[1] + ntpVer[2] + "." + ntpVer[3];
        } else if( ntpVer[2] =~ "[a-z][0-9]+" ) {
          ntpVer = ntpVer[1] + ntpVer[2];
        } else {
          ntpVer = ntpVer[1];
        }
      } else {
        ntpVer = "unknown";
      }

      set_kb_item( name:"NTP/Linux/Ver", value:ntpVer );

      cpe = build_cpe( value:ntpVer, exp:"^([0-9.]+[a-z0-9A-Z.]+?)", base:"cpe:/a:ntp:ntp:" );
      if( ! cpe )
        cpe = "cpe:/a:ntp:ntp";

      install = port + "/udp";
      register_product( cpe:cpe, location:install, port:port, service:"ntp" );
    }

    report = 'It is possible to determine a lot of information about the remote host by querying ' +
             'the NTP (Network Time Protocol) variables - these include OS descriptor, and time settings.\n\n' +
             'It was possible to gather the following information from the remote NTP host : \n\n' + list + '\n' +
             'Quickfix: Restrict default access to ignore all info packets.';

    log_message( port:port, protocol:proto, data:report );
    exit( 0 );
  }
}

exit( 0 );
