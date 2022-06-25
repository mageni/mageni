###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_asp_dotnet_sec_bypass_vuln_july18.nasl 12410 2018-11-19 10:06:05Z cfischer $
#
# Microsoft ASP.NET Core Security Feature Bypass Vulnerability July18
#
# Authors:
# Rinu Kuriaksoe <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813674");
  script_version("$Revision: 12410 $");
  script_cve_id("CVE-2018-8171");
  script_bugtraq_id(104659);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 11:06:05 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-07-13 15:50:36 +0530 (Fri, 13 Jul 2018)");
  script_name("Microsoft ASP.NET Core Security Feature Bypass Vulnerability July18");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (CVE-2018-8171).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because system does not properly
  validate the number of incorrect login attempts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security controls on the target system.");

  script_tag(name:"affected", value:"Any ASP.NET Core based application that uses
  'Microsoft.AspNetCore.Identity' with versions 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4,
  1.0.5. 1.1.0, 1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 2.0.0, 2.0.1, 2.0.2, 2.0.3,
  2.1.0, 2.1.1.");

  script_tag(name:"solution", value:"Upgrade 'Microsoft.AspNetCore.Identity' package
  versions to 1.0.6 or 1.1.6 or 2.0.4 or 2.1.2 or later. Please see the references
  for more info.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8171");
  script_xref(name:"URL", value:"https://github.com/aspnet/announcements/issues/310");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
fileList = wmi_file_fileversion( handle:handle, fileName:"Microsoft.AspNetCore.Identity", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

report = "";  # nb: To make openvas-nasl-lint happy...

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_in_range( version:version[1], test_version:"1.0", test_version2:"1.0.5" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"1.0.6" ) + '\n';
    } else if( version_in_range( version:version[1], test_version:"1.1", test_version2:"1.1.5" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"1.1.6" ) + '\n';
    } else if( version_in_range( version:version[1], test_version:"2.0", test_version2:"2.0.3" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"2.0.4" ) + '\n';
    } else if( version_in_range( version:version[1], test_version:"2.1", test_version2:"2.1.1" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"2.1.2" ) + '\n';
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 99 );
}

exit( 99 );