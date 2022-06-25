###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4054519)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812244");
  script_version("2019-05-17T13:14:58+0000");
  script_cve_id("CVE-2017-11885", "CVE-2017-11886", "CVE-2017-11887", "CVE-2017-11890",
                "CVE-2017-11894", "CVE-2017-11895", "CVE-2017-11901", "CVE-2017-11903",
                "CVE-2017-11906", "CVE-2017-11907", "CVE-2017-11912", "CVE-2017-11913",
                "CVE-2017-11919", "CVE-2017-11927", "CVE-2017-11930");
  script_bugtraq_id(102055, 102062, 102063, 102082, 102053, 102054, 102046, 102047,
                    102078, 102045, 102092, 102091, 102093, 102095, 102058);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 13:14:58 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-12-13 09:23:14 +0530 (Wed, 13 Dec 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4054519)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4054519");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - An error in RPC if the server has Routing and Remote Access enabled.

  - Internet Explorer improperly accesses objects in memory.

  - Internet Explorer improperly handles objects in memory.

  - Scripting engine handles objects in memory in Microsoft browsers.

  - Windows its:// protocol handler unnecessarily sends traffic to a remote
    site in order to determine the zone of a provided URL.

  - Scripting engine does not properly handle objects in memory in Microsoft
    browsers.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited this vulnerability to execute code on the target
  system, gain the same user rights as the current user, obtain information to
  further compromise the user's system and could attempt a brute-force attack to
  disclose the password.");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4054519");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.18872"))
{
  report = report_fixed_ver( file_checked:sysPath + "\Win32k.sys",
                             file_version:fileVer, vulnerable_range:"Less than 6.3.9600.18872" );
  security_message(data:report);
  exit(0);
}
exit(0);
