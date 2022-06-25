###############################################################################
# OpenVAS Vulnerability Test
# $Id: zone_alarm_local_dos.nasl 10200 2018-06-14 14:39:20Z cfischer $
#
# ZoneAlarm Pro local DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

#  Ref: bipin gautam <visitbipin@yahoo.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14726");
  script_version("$Revision: 10200 $");
  script_cve_id("CVE-2004-2713");
  script_tag(name:"last_modification", value:"$Date: 2018-06-14 16:39:20 +0200 (Thu, 14 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_name("ZoneAlarm Pro local DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Firewalls");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"ZoneAlarm Pro firewall runs on this host.

  This version contains a flaw that may allow a local denial of service. To
  exploit this flaw, an attacker would need to temper with the files located in
  %windir%/Internet Logs. An attacker may modify them and prevent ZoneAlarm
  to start up properly.");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if( ! registry_key_exists( key:key ) ) exit( 0 );

foreach item( registry_enum_keys( key:key ) ) {

  name = registry_get_sz( key:key + item, item:"DisplayName" );

  if( "ZoneAlarm Pro" >< name ) {

    version = registry_get_sz( key:key + item, item:"DisplayVersion" );
    if( version ) {

      set_kb_item( name:"zonealarm/version", value:version );

      register_and_report_cpe( app:"ZoneAlarm Pro", ver:version, concluded:version, base:"cpe:/a:zonelabs:zonealarm:", expr:"^([0-9.]+)" );

      if( ereg( pattern:"[1-4]\.|5\.0\.|5\.1\.", string:version ) ) {
        security_message( port:0, data:"The target host was found to be vulnerable." );
      }
    }
  }
}

exit( 0 );