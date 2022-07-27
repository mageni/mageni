###############################################################################
# OpenVAS Vulnerability Test
#
# MS SharePoint Server and Foundation Multiple Vulnerabilities (3124585)
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806660");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2016-0011", "CVE-2015-6117");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-01-13 12:19:11 +0530 (Wed, 13 Jan 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("MS SharePoint Server and Foundation Multiple Vulnerabilities (3124585)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-004.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to improper Access
  Control Policy (ACP) configuration settings.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform elevated privilege
  actions on the target.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013 Service Pack 1 and

  Microsoft SharePoint Foundation 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3114503");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-004");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if( ! infos = get_app_version_and_location( cpe:CPE ) )
  if( ! infos = get_app_version_and_location( cpe:'cpe:/a:microsoft:sharepoint_foundation', exit_no_version:TRUE ) ) exit( 0 );

shareVer = infos['version'];
if(!shareVer){
  exit(0);
}

path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

##SharePoint Server 2013 File Info not available
##Need to update for SharePoint Server 2013

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
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4787.999"))
      {
        report = 'File checked:     ' +  path1 + "Wsssetup.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: 15 - 15.0.4787.999' + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}

exit(99);