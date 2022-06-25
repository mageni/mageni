###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4048959)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812139");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-11869", "CVE-2017-11768", "CVE-2017-11788", "CVE-2017-11880",
                "CVE-2017-11791", "CVE-2017-11827", "CVE-2017-11834", "CVE-2017-11842",
                "CVE-2017-11843", "CVE-2017-11846", "CVE-2017-11847", "CVE-2017-11848",
                "CVE-2017-11849", "CVE-2017-11850", "CVE-2017-11851", "CVE-2017-11853",
                "CVE-2017-11855", "CVE-2017-11858", "CVE-2017-11831", "CVE-2017-11832");
  script_bugtraq_id(101742, 101705, 101711, 101755, 101715, 101703, 101725, 101719, 101740,
	            101741, 101729, 101709, 101762, 101738, 101763, 101764, 101751, 101716,
	            101721, 101726);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-15 10:19:08 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4048959)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4048959");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This security update includes improvements and
  fixes.

  - Addressed issue where the virtual smart card doesn't assess the Trusted Platform
    Module (TPM) vulnerability correctly.

  - Addressed issue where applications based on the Microsoft JET Database Engine
    fail when creating or opening Microsoft Excel .xls files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode, to cause a remote denial of service against
  a system. Also could obtain information to further compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4048959");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Mshtml.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.9200.22297"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Mshtml.dll",
                            file_version:fileVer, vulnerable_range:"Less than 10.0.9200.22297");
  security_message(data:report);
  exit(0);
}
exit(0);
