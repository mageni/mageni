###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office 2013 Service Pack 1 Information Disclosure Vulnerability (KB4011277)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812249");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-11934");
  script_bugtraq_id(102064);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-12-13 12:08:40 +0530 (Wed, 13 Dec 2017)");
  script_name("Microsoft Office 2013 Service Pack 1 Information Disclosure Vulnerability (KB4011277)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4011277");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Microsoft Office
  improperly discloses the contents of its memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who exploited the vulnerability to use the information to compromise the user's
  computer or data.");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011277");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

if(officeVer && officeVer =~ "^15\.")
{
  os_arch = get_kb_item("SMB/Windows/Arch");
  if(!os_arch){
    exit(0);
  }

  if("x86" >< os_arch){
    key_list = make_list("SOFTWARE\Microsoft\Office\15.0\Access\InstallRoot");
  }
  else if("x64" >< os_arch){
    key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Office\15.0\Access\InstallRoot",
                          "SOFTWARE\Microsoft\Office\15.0\Access\InstallRoot");
  }

  foreach key (key_list)
  {
    comPath = registry_get_sz(key:key, item:"Path");
    if(comPath)
    {
      ortVer = fetch_file_version(sysPath:comPath, file_name:"Oart.dll");
      if(ortVer && ortVer =~ "^(15\.)")
      {
        if(version_is_less(version:ortVer, test_version:"15.0.4989.1000"))
        {
          report = report_fixed_ver( file_checked:comPath + "Oart.dll",
                                     file_version:ortVer, vulnerable_range:"15.0 - 15.0.4989.999" );
          security_message(data:report);
          exit(0);
        }
      }
    }
  }
}
exit(0);
