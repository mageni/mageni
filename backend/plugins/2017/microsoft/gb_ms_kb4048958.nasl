###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4048958)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812207");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-11827", "CVE-2017-11831", "CVE-2017-11768", "CVE-2017-11788",
                "CVE-2017-11880", "CVE-2017-11791", "CVE-2017-11834", "CVE-2017-11837",
                "CVE-2017-11838", "CVE-2017-11842", "CVE-2017-11843", "CVE-2017-11846",
                "CVE-2017-11847", "CVE-2017-11848", "CVE-2017-11849", "CVE-2017-11850",
                "CVE-2017-11851", "CVE-2017-11853", "CVE-2017-11855", "CVE-2017-11856",
                "CVE-2017-11858", "CVE-2017-11869");
  script_bugtraq_id(101482);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-11-15 10:47:54 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4048958)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4041693");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Windows Media Player improperly discloses file information.

  - Windows Search improperly handles objects in memory.

  - Windows kernel fails to properly initialize a memory address.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited this vulnerabilities to obtain information to further
  compromise the user's system, cause a remote denial of service against a system
  and allow to test for the presence of files on disk.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4048958");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
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

if(version_is_less(version:fileVer, test_version:"11.0.9600.18838"))
{
  report = report_fixed_ver( file_checked:sysPath + "\Mshtml.dll",
                             file_version:fileVer, vulnerable_range:"Less than 11.0.9600.18838" );
  security_message(data:report);
  exit(0);
}
exit(0);
