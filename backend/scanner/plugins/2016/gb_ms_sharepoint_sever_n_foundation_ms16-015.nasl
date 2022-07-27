###############################################################################
# OpenVAS Vulnerability Test
#
# MS SharePoint Server and Foundation Multiple Vulnerabilities (3134226)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:sharepoint_foundation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809708");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-0022", "CVE-2016-0052", "CVE-2016-0053", "CVE-2016-0039");
  script_bugtraq_id(82508, 82652, 82787, 82512);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-10-19 15:25:36 +0530 (Wed, 19 Oct 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS SharePoint Server and Foundation Multiple Vulnerabilities (3134226)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-015.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist as office software fails
  to properly handle objects in memory and sharePoint server does not properly
  sanitize a specially crafted web request to an affected SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to run arbitrary code in the context of the current user and perform
  XSS attacks.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013 Service Pack 1,

  Microsoft SharePoint Foundation 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114733");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3039768");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Foundation/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)){
  exit(0);
}

shareVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## File information not available for SharePoint Server 2013
## https://support.microsoft.com/en-us/kb/3039768
## Foundation 2013
if(shareVer =~ "^15\..*")
{
  path1 = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path1)
  {
    path1 = path1 + "\microsoft shared\SERVER15\Server Setup Controller";

    dllVer = fetch_file_version(sysPath:path1, file_name:"Wsssetup.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4797.999"))
      {
        report = 'File checked:     ' +  path1 + "Wsssetup.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: 15 -15.0.4797.999' + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

exit(99);