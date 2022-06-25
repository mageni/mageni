###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server Multiple Vulnerabilities (2952166)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804580");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2014-0251", "CVE-2014-1754");
  script_bugtraq_id(67283, 67288);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2014-05-14 12:56:31 +0530 (Wed, 14 May 2014)");
  script_name("Microsoft SharePoint Server Multiple Vulnerabilities (2952166)");

  script_tag(name:"summary", value:"This host is missing an critical security update according to Microsoft
  Bulletin MS14-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws is due to multiple unspecified components when handling page content.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2007 Service Pack 32/64 bit,

  Microsoft SharePoint Server 2010 Service Pack 2 and prior,

  Microsoft SharePoint Server 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57834");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-022");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
shareVer = infos['version'];

## SharePoint Server 2007
## For this kb2596763 not able to find any file
if(shareVer =~ "^12\.")
{
  path = infos['location'];
  if(!path || "Could not find the install location" >< path){
    exit(0);
  }

  exeVer = fetch_file_version(sysPath:path,
            file_name:"\12.0\Bin\Microsoft.Office.Server.Conversions.Launcher.exe");
  if(exeVer)
  {
    if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6690.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## SharePoint Server 2010 (wosrv & coreserver)
if(shareVer =~ "^14\.")
{
  key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\";
  if(!registry_key_exists(key:key)){
    exit(0);
  }

  path = registry_get_sz(key: key + "14.0", item:"Location");

  dllVer = fetch_file_version(sysPath:path, file_name:"ISAPI\Microsoft.office.server.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7118.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## SharePoint Server 2013 (coreserverloc)
if(shareVer =~ "^15\.")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\SERVER15\Server Setup Controller\WSS.en-us";

    dllVer2 = fetch_file_version(sysPath:path, file_name:"SSETUPUI.DLL");
    if(dllVer2)
    {
      if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4569.999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

exit(99);