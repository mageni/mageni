###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_smb_lsc_fetch_file_ver.nasl 12770 2018-12-12 10:35:08Z cfischer $
#
# SMB: Gather file version info for authenticated scans
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108517");
  script_version("$Revision: 12770 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-12 11:35:08 +0100 (Wed, 12 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-12 10:15:08 +0100 (Wed, 12 Dec 2018)");
  script_name("SMB: Gather file version info for authenticated scans");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"summary", value:"This script gathers the version of various
  Microsoft Windows files and saves/caches them internally for faster access by
  other scripts during authenticated scans.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = smb_get_system32root();
if( ! sysPath )
  exit( 0 );

# nb: Can be used by smb_get_fileversion_from_cache() from secpod_smb_func.inc
# to avoid that VTs depending on the version of common files needs to call
# the fetch_file_version() function on their own and thus would require a
# script_require_ports(139, 445) which might slow down scans due to
# "non_simult_ports" of the scanner set to 139 and 445.
foreach file( make_list( "edgehtml.dll", "mshtml.dll" ) ) {
  vers = fetch_file_version( sysPath:sysPath, file_name:file );
  if( vers && vers =~ "^[0-9]+\." ) {
    set_kb_item( name:"SMB/lsc_file_version_cache/available", value:TRUE );
    set_kb_item( name:"SMB/lsc_file_version_cache/" + file + "/available", value:TRUE );
    set_kb_item( name:"SMB/lsc_file_version_cache/" + file + "/infos", value:sysPath + "\" + file + "#--#" + vers );
  }
}

exit( 0 );