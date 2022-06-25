###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asp_dotnet_core_dos_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Microsoft ASP.NET Core Denial of Service Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812099");
  script_version("$Revision: 11983 $");
  script_cve_id("CVE-2017-11883");
  script_bugtraq_id(101835);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-20 15:14:33 +0530 (Mon, 20 Nov 2017)");
  script_name("Microsoft ASP.NET Core Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-11883");
  script_xref(name:"URL", value:"https://github.com/aspnet/announcements/issues/278");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (CVE-2017-11883).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in ASP.NET
  Core which improperly handles certain crafted web requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft ASP.NET Core 1.0 using packages
  'Microsoft.AspNetCore.Server.WebListener' and 'Microsoft.Net.Http.Server'
  with version 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4 or 1.0.5. Microsoft ASP.NET Core 1.1
  using packages 'Microsoft.AspNetCore.Server.WebListener' and
  'Microsoft.Net.Http.Server' with version 1.1.0, 1.1.1, 1.1.2 or 1.1.3. Microsoft
  ASP.NET Core 2.0 using packages 'Microsoft.AspNetCore.Server.HttpSys' with version
  2.0.0 and 2.0.1.");

  script_tag(name:"solution", value:"Upgrade Microsoft ASP.NET Core 1.0 to use
  package 'Microsoft.AspNetCore.Server.WebListener' and 'Microsoft.Net.Http.Server'
  version 1.0.6 or later. Also upgrade Microsoft ASP.NET Core 1.1 to use package
  'Microsoft.AspNetCore.Server.WebListener' and 'Microsoft.Net.Http.Server' version
  1.1.4 or later. Upgrade Microsoft ASP.NET Core 2.0 to use package
  'Microsoft.AspNetCore.Server.HttpSys' version 2.0.2 or later.
  Plese see the references for more info.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path
fileList1 = wmi_file_fileversion( handle:handle, fileName:"Microsoft.AspNetCore.Server.WebListener", fileExtn:"dll", includeHeader:FALSE );
fileList2 = wmi_file_fileversion( handle:handle, fileName:"Microsoft.Net.Http.Server", fileExtn:"dll", includeHeader:FALSE );
fileList3 = wmi_file_fileversion( handle:handle, fileName:"Microsoft.AspNetCore.Server.HttpSys", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList1 && ! fileList2 && ! fileList3 ) {
  exit( 0 );
}

report = "";

if( fileList1 && is_array( fileList1 ) ) {

  foreach filePath1( keys( fileList1 ) ) {

    vers1 = fileList1[filePath1];

    if( vers1 && version1 = eregmatch( string:vers1, pattern:"^([0-9.]+)" ) ) {

      if( version1[1] =~ "^1\.0" && version_is_less( version:version1[1], test_version:"1.0.6" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version1[1], file_checked:filePath1, fixed_version:"1.0.6" ) + '\n';
      } else if( version1[1] =~ "^1\.1" && version_is_less( version:version1[1], test_version:"1.1.4" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version1[1], file_checked:filePath1, fixed_version:"1.1.4" ) + '\n';
      }
    }
  }
}

if( fileList2 && is_array( fileList2 ) ) {

  foreach filePath2( keys( fileList2 ) ) {

    vers2 = fileList2[filePath2];

    if( vers2 && version2 = eregmatch( string:vers2, pattern:"^([0-9.]+)" ) ) {

      if( version2[1] =~ "^1\.0" && version_is_less( version:version2[1], test_version:"1.0.6" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version2, file_checked:filePath2, fixed_version:"1.0.6" ) + '\n';
      } else if( version2[1] =~ "^1\.1" && version_is_less( version:version2[1], test_version:"1.1.4" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version2[1], file_checked:filePath2, fixed_version:"1.1.4" ) + '\n';
      }
    }
  }
}

if( fileList3 && is_array( fileList3 ) ) {

  foreach filePath3( keys( fileList3 ) ) {

    vers3 = fileList3[filePath3];

    if( vers3 && version3 = eregmatch( string:vers3, pattern:"^([0-9.]+)" ) ) {

      if( version3[1] =~ "^2\.0" && version_is_less( version:version3[1], test_version:"2.0.2" ) ) {
        VULN = TRUE;
        report += report_fixed_ver( file_version:version3[1], file_checked:filePath3, fixed_version:"2.0.2" ) + '\n';
      }
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );