# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108590");
  script_version("2019-06-01T08:20:43+0000");
  script_tag(name:"last_modification", value:"2019-06-01 08:20:43 +0000 (Sat, 01 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-01 07:09:18 +0000 (Sat, 01 Jun 2019)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NTP Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("ntp/system_banner/available");

  script_tag(name:"summary", value:"This script performs NTP server based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

SCRIPT_DESC = "NTP Server OS Identification";
BANNER_TYPE = "NTP Server banner";

port = get_port_for_service( default:123, ipproto:"udp", proto:"ntp" );

if( ! banner = get_kb_item( "ntp/" + port + "/system_banner" ) )
  exit( 0 );

if( "linux" >< tolower( banner ) ) {
  if( "-gentoo" >< banner ) {
    register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( "-amazon" >< tolower( banner ) ) {
    register_and_report_os( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {

    # Linux/2.6.35em1-g9733209
    # Linux2.4.20_mvl31-bcm95836cpci
    # Linux2.2.13
    version = eregmatch( pattern:"Linux/?([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
  }
} else if( "windows" >< tolower( banner ) ) {
  register_and_report_os( os:os, cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
} else if( "unix" >< tolower( banner ) ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
} else if( "freebsd" >< tolower( banner ) ) {

  # FreeBSDJNPR-11.0-20180730.2cd3a6e_buil
  # FreeBSDJNPR-10.3-20170422.348838_build
  # FreeBSD/10.1-RELEASE-p25
  # FreeBSD/11.2-RELEASE-p6
  version = eregmatch( pattern:"FreeBSD(/|JNPR-)([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[2] ) ) {
    register_and_report_os( os:"FreeBSD", version:version[2], cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
} else if( "netbsd" >< tolower( banner ) ) {
  version = eregmatch( pattern:"NetBSD/([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"NetBSD", version:version[1], cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
} else if( "openbsd" >< tolower( banner ) ) {
  version = eregmatch( pattern:"OpenBSD/([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"OpenBSD", version:version[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
} else if( "sunos" >< tolower( banner ) ) {
  version = eregmatch( pattern:"SunOS/([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
} else if( "hp-ux" >< tolower( banner ) ) {
  version = eregmatch( pattern:"HP-UX/([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"HP-UX", version:version[1], cpe:"cpe:/o:hp:hp-ux", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"HP-UX", cpe:"cpe:/o:hp:hp-ux", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
} else if( "data ontap" >< tolower( banner ) ) {

  # Data ONTAP/8.2.4P1
  # Data ONTAP/8.2.5
  # Data ONTAP/9.4P1
  version = eregmatch( pattern:"Data ONTAP/([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"NetApp Data ONTAP", version:version[1], cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
} else {
  # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
  register_and_report_os( os:os, banner_type:banner_type, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"ntp_banner", port:port, proto:"udp" );
}

exit( 0 );
