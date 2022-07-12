###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_superantispyware_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# SuperAntiSpyware Product Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113098");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-02-01 11:48:55 +0100 (Thu, 01 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("SuperAntiSpyware Product detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Windows/Arch");

  script_tag(name:"summary", value:"The script checks if SuperAntiSpyware is installed on the target host, and, if so, detects the installed version.
  This is done by searching the registry using SMB");

  script_xref(name:"URL", value:"http://www.superantispyware.com/");

  exit(0);
}

include( "secpod_smb_func.inc" );
include( "host_details.inc" );
include( "smb_nt.inc" );
include( "cpe.inc" );

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach item( registry_enum_keys( key: key ) ) {

  display_name = registry_get_sz( key: key + item, item: "DisplayName" );

  if( "SUPERAntiSpyware" >< display_name ) {
    set_kb_item( name: "superantispyware/detected", value: TRUE );

    version = registry_get_sz( key: key + item, item: "DisplayVersion" );
    if( version ) {
       set_kb_item( name: "superantispyware/version", value: version );
    }
    else {
      version = "unknown";
    }

    register_and_report_cpe( app: "SuperAntiSpyware", ver: version, base: "cpe:/a:superantispyware:superantispyware:", expr: "([0-9.]+)" );
    break;
  }
}

exit( 0 );
