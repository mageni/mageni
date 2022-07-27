###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft SharePoint Server Information Disclosure Vulnerability (2827663)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811595");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2013-1290");
  script_bugtraq_id(58844);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-04 13:15:44 +0530 (Mon, 04 Sep 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft SharePoint Server Information Disclosure Vulnerability (2827663)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS13-030");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to certain configurations
  involving legacy My Sites, does not properly establish default access
  controls for a SharePoint list.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  information disclosure if an attacker determined the address or location of a
  specific SharePoint list and gained access to the SharePoint site where the
  list is maintained. The attacker would need to be able to satisfy the
  SharePoint site's authentication requests to exploit this vulnerability.");

  script_tag(name:"affected", value:"Microsoft SharePoint Server 2013.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/2737969");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms13-030");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Server/Ver");
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

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## SharePoint Server 2013 (coreserverloc)
if(shareVer =~ "^15\..*")
{
  path = registry_get_sz(key: key + "15.0", item:"Location");

  dllVer = fetch_file_version(sysPath:path, file_name:"ISAPI\Microsoft.office.server.dll");
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"15.0.4481.1507"))
    {
      report = 'File checked:     ' +  path + "\ISAPI\Microsoft.office.server.dll"+ '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: Less than 15.0.4481.1507\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
