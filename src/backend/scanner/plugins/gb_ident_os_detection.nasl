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
  script_oid("1.3.6.1.4.1.25623.1.0.108565");
  script_version("2019-05-24T07:46:22+0000");
  script_tag(name:"last_modification", value:"2019-05-24 07:46:22 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-18 09:50:47 +0000 (Thu, 18 Apr 2019)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Identification Protocol (ident) Service OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("ident_process_owner.nasl", "slident.nasl");
  script_mandatory_keys("ident/os_banner/available");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc1413");

  script_tag(name:"summary", value:"This script performs an OS detection based on services supporting
  the Identification Protocol (ident).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

SCRIPT_DESC = "Identification Protocol (ident) Service OS Identification";
BANNER_TYPE = "Identification Protocol (ident) Service OS banner";

port  = get_port_for_service( default:113, proto:"auth" );
os    = get_kb_item( "ident/" + port + "/os_banner/os_only" );
concl = get_kb_item( "ident/" + port + "/os_banner/full" );
if( ! os || ! concl || egrep( string:os, pattern:"^[0-9]+$" ) ) # nb: slident.nasl and ident_process_owner.nasl are verifying this but just in case the scripts are changed...
  exit( 0 );

os = tolower( os );

# e.g.
# 113 , 38352 : USERID : OTHER :99
# 53,35089:USERID:UNIX:pdns
# 113 , 60954 : USERID : 20 : oidentd
# 113 , 53004 : USERID : FreeBSD : nouser
# 113 , 51909 : USERID : Linux :root
# 113,53740:USERID:16:oident
# 113 , 50548 : USERID : 10 : root
# 113 , 60824 : USERID : SUNOS : root
# 113 , 41433 : USERID : OS/2 : dixie
# 113, 49504 : USERID : WinXP : NBK
# 113, 37372 : USERID : WINDOWS : carr
# 113,60662 : USERID : WIN32 :<spaces>
# 113, 53198 : USERID : Windows : jimmycee
# see also https://tools.ietf.org/html/rfc1413 and https://www.iana.org/assignments/operating-system-names/operating-system-names.xhtml#operating-system-names-1
#
# Have seen also a few of those (including the newline) which are likely Apple iOS and not Cisco IOS:
# 113,55972
#  : USERID : iOS : dragon2

if( "windows" >< os || "win32" >< os ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"windows", port:port );
} else if( "winxp" >< os ) {
  register_and_report_os( os:"Microsoft Windows XP", cpe:"cpe:/o:microsoft:windows_xp", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"windows", port:port );
} else if( "linux" >< os || "unix" >< os ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide", port:port );
} else if( "sunos" >< os ) {
  register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide", port:port );
} else if( "os/2" >< os ) {
  register_and_report_os( os:"IBM OS/2", cpe:"cpe:/o:ibm:os2", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide", port:port );
} else if( "freebsd" >< os ) {
  register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide", port:port );
} else if( os == "ios" ) {
  register_and_report_os( os:"Apple iOS", cpe:"cpe:/o:apple:iphone_os", banner_type:BANNER_TYPE, banner:concl, desc:SCRIPT_DESC, runs_key:"unixoide", port:port );
} else {
  if( "unknown" >!< os && "other" >!< os ) {
    register_unknown_os_banner( banner:concl, banner_type_name:BANNER_TYPE, banner_type_short:"ident_os_banner", port:port );
  }
}

exit( 0 );