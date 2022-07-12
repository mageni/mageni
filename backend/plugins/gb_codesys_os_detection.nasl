###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codesys_os_detection.nasl 12655 2018-12-04 15:38:08Z cfischer $
#
# CODESYS Service OS Identification
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108494");
  script_version("$Revision: 12655 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:38:08 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-04 13:25:20 +0100 (Tue, 04 Dec 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("CODESYS Service OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_codesys_detect.nasl");
  script_mandatory_keys("codesys/detected");

  script_tag(name:"summary", value:"This script performs OS detection on devices with
  a CODESYS programming interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

SCRIPT_DESC = "CODESYS Service OS Identification";
BANNER_TYPE = "CODESYS Service information";

port = get_kb_item( "Services/codesys" );
if( ! port )
  port = 2455;

if( ! os_name = get_kb_item( "codesys/" + port + "/os_name" ) )
  exit( 0 );

if( ! os_details = get_kb_item( "codesys/" + port + "/os_details" ) )
  exit( 0 );

report_banner  = '\nOS Name:    ' + os_name;
report_banner += '\nOS Details: ' + os_details;

if( os_name == "Windows" ) {

  # CE 5.0
  # CE.net (4.20) [runtime port v2
  # unknown CE version [runtime por
  # CE.net (4.x)

  ce_ver = eregmatch( pattern:"^CE ([0-9.]+)", string:os_details );
  if( ! isnull( ce_ver[1] ) ) {
    register_and_report_os( os:"Microsoft Windows CE", version:ce_ver[1], cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  ce_ver = eregmatch( pattern:"^CE\.net \(([0-9.x]+)", string:os_details );
  if( ! isnull( ce_ver[1] ) ) {
    register_and_report_os( os:"Microsoft Windows CE.net", version:ce_ver[1], cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( "unknown CE version" >< os_details ) {
    register_and_report_os( os:"Microsoft Windows CE", cpe:"cpe:/o:microsoft:windows_ce", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  if( "NT/2000/XP" >< os_details ) {
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  register_unknown_os_banner( banner:report_banner, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );

} else if( os_name == "Linux" ) {

  # os_name: Linux
  # os_detail: 3.18.13-rt10-w02.00.03+3 [runti
  # os_detail: 4.9.47-rt37-w02.02.00_01+10 [ru
  # os_detail: 2.6.29.6-rt24atom
  # os_name: RTLinux
  # os_detail: 2.4.31-adeos
  version = eregmatch( pattern:"^([0-9.]+)", string:os_details );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

} else if( os_name == "Nucleus PLUS" ) {

  # os_name: Nucleus PLUS
  # os_detail: Nucleus PLUS version unknown
  register_and_report_os( os:"Nucleus RTOS", cpe:"cpe:/o:mentor:nucleus_rtos", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );

  if( "Nucleus PLUS version unknown" >< os_details )
    exit( 0 );

  # Havne't seen any other then Nucleus PLUS version unknown "live" so reporting an unknown OS for all others and exit previously
  register_unknown_os_banner( banner:report_banner, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );

} else if( os_name == "VxWorks" ) {

  # os_name: VxWorks
  # os_detail: 5.5.1 [runtime port v0 (2.4.7.0
  version = eregmatch( pattern:"^([0-9.]+)", string:os_details );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Wind River VxWorks", version:version[1], cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

} else if( os_name == "@CHIP-RTOS" ) {

  # os_name: @CHIP-RTOS
  # os_detail: SC123/SC143 V2.03 FULL
  # os_detail: SC23/SC24 V1.81 Beta Test versi
  version = eregmatch( pattern:"^[^ ]+ V([0-9.]+)", string:os_details );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"@CHIP-RTOS", version:version[1], cpe:"cpe:/o:beck-ipc:chip-rtos", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"@CHIP-RTOS", cpe:"cpe:/o:beck-ipc:chip-rtos", banner_type:BANNER_TYPE, port:port, banner:report_banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

} else {
  register_unknown_os_banner( banner:report_banner, banner_type_name:BANNER_TYPE, banner_type_short:"codesys_banner", port:port );
}

exit( 0 );