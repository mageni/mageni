###############################################################################
# OpenVAS Vulnerability Test
#
# MS SharePoint Server and Foundation Remote Code Execution Vulnerability (3058083)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805179");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-1700");
  script_bugtraq_id(74480);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-05-13 12:54:36 +0530 (Wed, 13 May 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS SharePoint Server and Foundation Remote Code Execution Vulnerability (3058083)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-047.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of page
  content that has been supplied to the server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated remote attacker to execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2007 Service Pack 3 32/64 bit,

  Microsoft SharePoint Foundation 2010 Service Pack 2,

  Microsoft SharePoint Foundation 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3058083");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-047");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server_or_Foundation_or_Services/Installed");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

shareVer = get_app_version(cpe:CPE);
if(!shareVer)
{
  CPE = "cpe:/a:microsoft:sharepoint_foundation";
  shareVer = get_app_version(cpe:CPE);
  if(!shareVer){
    exit(0);
  }
}

## SharePoint Server and Foundation 2007
if(shareVer =~ "^12\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\Microsoft Shared\web server extensions\12\ISAPI";

    dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.sharepoint.portal.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6721.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## SharePoint Server and Foundation 2010
if(shareVer =~ "^14\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\Microsoft Shared\web server extensions\14\ISAPI";

    dllVer = fetch_file_version(sysPath:path, file_name:"microsoft.sharepoint.portal.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7149.4999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}

## SharePoint Server and Foundation 2013
if(shareVer =~ "^15\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\SERVER15\Server Setup Controller";

    dllVer = fetch_file_version(sysPath:path, file_name:"Wsssetup.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4719.999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
