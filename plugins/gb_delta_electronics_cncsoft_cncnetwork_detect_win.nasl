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
  script_oid("1.3.6.1.4.1.25623.1.0.107647");
  script_version("2019-05-03T16:55:02+0000");
  script_tag(name:"last_modification", value:"2019-05-03 16:55:02 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2019-04-24 14:35:00 +0200 (Wed, 24 Apr 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Delta Electronics CNCSoft CNCNetwork Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_delta_electronics_cncsoft_detect_win.nasl");
  script_mandatory_keys("delta_electronics/cncsoft/suite/detected", "delta_electronics/cncsoft/suite/location");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Detects the installed version
  of Delta Electronics CNCSoft CNCNetwork for Windows.");

  script_xref(name:"URL", value:"http://www.deltaww.com/");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("cpe.inc");
include("host_details.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

if( ! loc = get_kb_item( "delta_electronics/cncsoft/suite/location" ) )
  exit( 0 );

location = loc + "CNCNetwork\";
filename = "CNCNetwork.exe";

version = fetch_file_version( sysPath:location, file_name:filename );
if( ! version )
  exit( 0 );

concluded = version + " from file " + location + filename;

set_kb_item( name:"delta_electronics/cncsoft/cncnetwork/detected", value:TRUE );

register_and_report_cpe( app:"Delta Electronics CNCSoft CNCNetwork", ver:version, concluded:concluded,
                         base:"cpe:/a:delta_electronics:cncsoft_cncnetwork:", expr:"^([0-9.]+)", insloc:location, regService:"smb-login", regPort:0 );

exit( 0 );