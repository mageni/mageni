###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server Remote Code Execution Vulnerability (2904244)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903331");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-5059");
  script_bugtraq_id(64081);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-01-08 15:22:36 +0530 (Wed, 08 Jan 2014)");
  script_name("Microsoft SharePoint Server Remote Code Execution Vulnerability (2904244)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS13-100.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Flaws is due to some input sanitisation errors related to SharePoint content");
  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013 (coreserverloc)");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code with
the privileges of the W3WP service account.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/55985");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS13-100");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-100");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

shareVer = get_app_version(cpe:CPE);
if(!shareVer){
  exit(0);
}

## SharePoint Server 2013 (coreserverloc)
if(shareVer =~ "^15\..*")
{
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                         item:"CommonFilesDir");
  if(path)
  {
    path = path + "\microsoft shared\SERVER15\Server Setup Controller\WSS.en-us";

    dllVer = fetch_file_version(sysPath:path, file_name:"SSETUPUI.DLL");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4442.999"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
