###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_schneider_electric_proface_gp-pro_ex_detect.nasl 13000 2019-01-09 14:50:02Z jschulte $
#
# Schneider Electric Proface GP-Pro EX Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113320");
  script_version("$Revision: 13000 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 15:50:02 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-09 14:42:30 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Schneider Electric Proface GP-Pro EX Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");

  script_tag(name:"summary", value:"Detection for Schneider Proface GP-Pro EX Software.");

  script_xref(name:"URL", value:"https://www.proface.com/en/product/soft/gpproex/top");

  exit(0);
}

CPE = "cpe:/a:schneider_electric:proface_gp-pro_ex:";

include( "host_details.inc" );
include( "smb_nt.inc" );
include( "secpod_smb_func.inc" );
include( "cpe.inc" );

if( ! os_arch = get_kb_item( "SMB/Windows/Arch" ) ) exit( 0 );

keys = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\", "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );

foreach key( keys ) {
  foreach item( registry_enum_keys( key: key ) ) {

    name = registry_get_sz( key: key + item, item: "DisplayName" );
    if( name !~ '^GP-Pro EX' ) continue;

    set_kb_item( name: "schneider_electric/proface_gp-pro_ex/detected", value: TRUE );

    if( ! version = registry_get_sz( key: key + item, item: "DisplayVersion" ) )
      version = "unknown";

    location = registry_get_sz( key: key + item, item: "InstallLocation" );

    register_and_report_cpe( app: "Schneider Electric Proface GP-Pro EX",
                             ver: version,
                             concluded: name,
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: location );

    exit( 0 );
  }
}

exit( 0 );
