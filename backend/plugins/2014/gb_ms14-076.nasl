###############################################################################
# OpenVAS Vulnerability Test
#
# MS Internet Information Services Security Feature Bypass Vulnerability (2982998)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805016");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-4078");
  script_bugtraq_id(70937);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-11-12 13:00:44 +0530 (Wed, 12 Nov 2014)");
  script_name("MS Internet Information Services Security Feature Bypass Vulnerability (2982998)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-076.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error within the
  Microsoft Internet Information Services (IIS) component.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services 8.0/8.5
  on Microsoft Windows 8 x32/x64 and Microsoft Windows 8.1 x32/x64 Edition");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60354");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2982998");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-076");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl", "gb_ms_iis_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IIS/Ver");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

iisVer = get_app_version(cpe:CPE);
if(!iisVer){
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win2012R2:1, win8_1:1,
                   win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\inetsrv\Iprestr.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"8.0.9200.17101")||
     version_in_range(version:dllVer, test_version:"8.0.9200.20000", test_version2:"8.0.9200.21217")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"8.5.9600.17265")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
