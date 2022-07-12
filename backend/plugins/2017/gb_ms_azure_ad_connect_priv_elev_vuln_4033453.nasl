###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Azure AD Connect Privilege Elevation Vulnerability (4033453)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811425");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2017-8613");
  script_bugtraq_id(99294);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-07-05 13:42:34 +0530 (Wed, 05 Jul 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Azure AD Connect Privilege Elevation Vulnerability (4033453)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Security Advisory 4033453");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to misconfiguration of
  Azure AD Connect Password writeback during enablement.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to reset passwords and gain unauthorized access to arbitrary
  on-premises AD privileged user accounts.");

  script_tag(name:"affected", value:"Azure AD Connect prior to 1.1.553.0");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/4033453");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

key = "Software\Microsoft\Azure AD Connect";
if(!registry_key_exists(key:key)){
  exit(0);
}

appPath = registry_get_sz(key:key, item:"WizardPath");
if("AzureADConnect" >< appPath)
{
  appPath = ereg_replace(pattern:"\AzureADConnect.exe", replace:"", string:appPath);
  dllVer = fetch_file_version(sysPath:appPath, file_name:"AzureADConnect.exe");
  if(dllVer)
  {
    if(version_is_less(version:dllVer, test_version:"1.1.553.0"))
    {
      report = 'File checked:     ' +  appPath + "AzureADConnect.exe" + '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range:  Less than 1.1.553.0' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
