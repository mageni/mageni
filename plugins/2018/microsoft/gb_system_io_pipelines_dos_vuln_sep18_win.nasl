###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_system_io_pipelines_dos_vuln_sep18_win.nasl 13953 2019-03-01 08:57:48Z cfischer $
#
# 'System.IO.Pipelines' Denial of Service Vulnerability Sep18 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
##########################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814210");
  script_version("$Revision: 13953 $");
  script_cve_id("CVE-2018-8409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 09:57:48 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-14 16:54:50 +0530 (Fri, 14 Sep 2018)");
  script_name("'System.IO.Pipelines' Denial of Service Vulnerability Sep18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with 'System.IO.Pipelines'
  package and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error on how
  'System.IO.Pipelines' handles requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a denial of service against an application that is leveraging
  System.IO.Pipelines.");

  script_tag(name:"affected", value:"System.IO.Pipelines package version 4.5.0");

  script_tag(name:"solution", value:"Upgrade to  System.IO.Pipelines package
  version 4.5.1 or later. Please see the referenced links for more info.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8409");
  script_xref(name:"URL", value:"https://blogs.msdn.microsoft.com/dotnet/2018/09/11/net-core-september-2018-update");
  script_xref(name:"URL", value:"https://www.nuget.org/packages/System.IO.Pipelines");
  script_xref(name:"URL", value:"https://github.com/aspnet/announcements/issues/316");
  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/83");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

# TODO: Limit to a possible known common path
fileList = wmi_file_file_search( handle:handle, fileName:"system.io.pipelines.4.5.0", fileExtn:"nupkg", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

report = "";  # nb: To make openvas-nasl-lint happy...

foreach filePath( fileList ) {

  if( eregmatch( pattern:".*system.io.pipelines.4.5.0.nupkg", string:filePath ) ) {
    VULN = TRUE;
    report += report_fixed_ver( file_version:"4.5.0", file_checked:filePath, fixed_version:"4.5.1" ) + '\n';
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );