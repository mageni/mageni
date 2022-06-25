###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Bluetooth Stack Remote Code Execution Vulnerability (2566220)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902395");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_cve_id("CVE-2011-1265");
  script_bugtraq_id(48617);
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Bluetooth Stack Remote Code Execution Vulnerability (2566220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2532531");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-053");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.");

  script_tag(name:"affected", value:"Microsoft Windows Vista Service Pack 2 and prior

  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior");

  script_tag(name:"insight", value:"The flaw is due to the way an object in memory is accessed when it has
  not been correctly initialized or has been deleted.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS11-053.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("misc_func.inc");
include("wmi_file.inc");

if( hotfix_check_sp( winVista:3, win7:2, win7x64:2 ) <= 0 ) exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path
fileList = wmi_file_fileversion( handle:handle, fileName:"fsquirt", fileExtn:"exe", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

# Don't pass NULL to version functions below
maxVer = "unknown";
fix = "unknown";

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:maxVer ) ) {
      continue;
    } else {
      foundMax = TRUE;
      maxVer = version[1];
      maxPath = filePath;
    }
  }
}

if( foundMax ) {

  if( hotfix_check_sp( winVista:3 ) > 0 ) {

    SP = get_kb_item( "SMB/WinVista/ServicePack" );

    if( "Service Pack 1" >< SP ) {
      if( version_is_greater_equal( version:version[1], test_version:"6.1.6001.22204" ) ) {
        flag = TRUE;
      } else {
        fix = ">= 6.1.6001.22204";
      }
    }

    if( "Service Pack 2" >< SP ) {
      if( version_in_range( version:version[1], test_version:"6.0.6002.18005", test_version2:"6.0.6002.21999" ) ||
          version_is_greater_equal( version:version[1], test_version:"6.0.6002.22629" ) ) {
        flag = TRUE;
      } else {
        fix = ">= 6.0.6002.22629";
      }
    }
  }

  if( hotfix_check_sp( win7:2, win7x64:2 ) > 0 ) {
    if( version_in_range( version:version[1], test_version:"6.1.7600.16385", test_version2:"6.1.7600.19999" ) ||
        version_is_greater_equal( version:version[1], test_version:"6.1.7601.17514" ) ) {
      flag = TRUE;
    } else {
      fix = ">= 6.1.7601.17514";
    }
  }
}

if( ! flag ) {
  report = report_fixed_ver( file_version:maxVer, file_checked:maxPath, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );