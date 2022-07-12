###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office 2016 Remote Code Execution Vulnerability (KB3213551)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811788");
  script_version("2019-05-20T11:12:48+0000");
  script_cve_id("CVE-2017-8744");
  script_bugtraq_id(100748);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2017-10-04 13:06:13 +0530 (Wed, 04 Oct 2017)");
  script_name("Microsoft Office 2016 Remote Code Execution Vulnerability (KB3213551)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB3213551");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Microsoft
  Office software when it fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability could use a specially crafted file
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office version 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213551");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Office\16.0\Common\FilesPaths\");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Office\16.0\Common\FilesPaths\",
                       "SOFTWARE\Microsoft\Office\16.0\Common\FilesPaths\");
}


foreach key (key_list)
{
  filePath = registry_get_sz(key:key, item:"office.odf");
  if(filePath)
  {
    offPath = eregmatch(pattern:".*Microsoft Shared\\", string:filePath);
    if(!offPath){
      exit(0);
    }

    offPath = offPath[0] + "TEXTCONV";

    offdllVer = fetch_file_version(sysPath:offPath, file_name:"wpft532.cnv");
    if(!offdllVer){
      continue;
    }

    if(offdllVer =~ "^2012\.1600\." && version_is_less(version:offdllVer, test_version:"2012.1600.8326.2107"))
    {
      report = 'File checked:     ' + offPath + "\wpft532.cnv" + '\n' +
               'File version:     ' + offdllVer  + '\n' +
               'Vulnerable range: ' + "2012.1600.0.0 - 2012.1600.8326.2106" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
exit(0);
