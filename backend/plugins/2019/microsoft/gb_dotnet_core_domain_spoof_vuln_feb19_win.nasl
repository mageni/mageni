# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.814760");
  script_version("$Revision: 14086 $");
  script_cve_id("CVE-2019-0657");
  script_bugtraq_id(106890);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 10:05:57 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-26 15:47:32 +0530 (Tue, 26 Feb 2019)");
  script_name(".NET Core Domain Spoofing Vulnerability (February 2019)");

  script_tag(name:"summary", value:"This host is installed with 'System.Private.Uri'
  or 'Microsoft.NETCore.App' package and is prone to domain spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in .Net
  Framework API's in the way they parse URL's.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct spoofing attacks.");

  script_tag(name:"affected", value:"System.Private.Uri package with version 4.3.0
  and Microsoft.NETCore.App package with versions 2.1.x prior to 2.1.8, 2.2.x prior
  to 2.2.2");

  script_tag(name:"solution", value:"Upgrade toSystem.Private.Uri package to
  version 4.3.1 or later. Upgrade Microsoft.NETCore.App package to versions
  2.1.8 or 2.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/97");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0657");

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

fileList = wmi_file_file_search( handle:handle, fileName:"System.Private.Uri", includeHeader:TRUE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

report = "";  # nb: To make openvas-nasl-lint happy...

foreach filePath( fileList )
{
  if( eregmatch( pattern:".*system.private.uri.4.3.0", string:filePath))
  {
    VULN = TRUE;
    report += report_fixed_ver( file_version:"4.3.0", file_checked:filePath, fixed_version:"4.3.1" ) + '\n';
  }
}

if( VULN )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );