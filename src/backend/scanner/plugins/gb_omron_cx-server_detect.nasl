###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_omron_cx-server_detect.nasl 12685 2018-12-06 13:18:09Z jschulte $
#
# Omron CX-Server Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113307");
  script_version("$Revision: 12685 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-06 14:18:09 +0100 (Thu, 06 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-06 11:50:00 +0100 (Thu, 06 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("Omron CX-Server Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"Checks whether Omron CX-Server is installed
  on the target and if so, tries to figure out the version.");

  script_xref(name:"URL", value:"https://industrial.omron.eu/en/products/cx-server");

  exit(0);
}

CPE = "cpe:/a:omron:cx-server:";

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("http_func.inc");

base_key_one = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
base_key_two = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach keypart( make_list_unique( registry_enum_keys( key: base_key_one ), registry_enum_keys( key: base_key_two ) ) ) {

  key = base_key_one + keypart;
  if( ! registry_key_exists( key: key ) ) {
    key = base_key_two + keypart;
    if( ! registry_key_exists( key: key ) ) continue;
  }

  name = registry_get_sz( key: key, item: "DisplayName" );
  if( name !~ '^CX[- ]Server' || name =~ 'Driver' ) continue;
  set_kb_item( name: "omron/cx-server/detected", value: TRUE );
  version = "unknown";

  # For future notice, thought I'd add it here:
  # If one day a customer remarks that this doesn't detect the version reliably
  # (maybe because Omron changes how they set their registry keys)
  # The items "VersionMajor" and "VersionMinor" will contain hex-representations
  # of the major, respectively minor, version.

  # Though Omron advocates their version like this: 3.4.1.0 on their website,
  # they actually just follow a major.minor.patch pattern, so 3.41.0 for example
  vers = registry_get_sz( key: key, item: "DisplayVersion" );
  if( ! isnull( vers ) && vers != "" ) {
    version = vers;
    set_kb_item( name: "omron/cx-server/version", value: version );
  }

  insloc = registry_get_sz( key: key, item: "InstallLocation" );

  register_and_report_cpe( app: "Omron CX-Server",
                           ver: version,
                           concluded: version,
                           base: CPE,
                           expr: '([0-9.]+)',
                           insloc: insloc );

  exit( 0 );
}

exit( 0 );
