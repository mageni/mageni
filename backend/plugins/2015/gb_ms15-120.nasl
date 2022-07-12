###############################################################################
# OpenVAS Vulnerability Test
#
# MS Windows IPSec Denial of Service Vulnerability (3102939)
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805775");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2015-6111");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2015-11-11 08:52:04 +0530 (Wed, 11 Nov 2015)");
  script_name("MS Windows IPSec Denial of Service Vulnerability (3102939)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-120.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to the Internet Protocol
  Security (IPSec) service improperly handles encryption negotiation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct denial-of-service attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64
  Microsoft Windows 8.1 x32/x64
  Microsoft Windows Server 2012
  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3102939");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms15-120");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1,
                   win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

bfeVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Bfe.dll");
if(!bfeVer){
  exit(0);
}

## Win 8 and 2012
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:bfeVer, test_version:"6.2.9200.17539"))
  {
    Vulnerable_range = "Less than 6.2.9200.17539";
    VULN = TRUE ;
  }
  else if(version_in_range(version:bfeVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21655"))
  {
    Vulnerable_range = "6.2.9200.21000 - 6.2.9200.21655";
    VULN = TRUE ;
  }
}

## Win 8.1 and win2012R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  if(version_is_less(version:bfeVer, test_version:"6.3.9600.18009"))
  {
    Vulnerable_range = "Less than 6.3.9600.18009";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "system32\Bfe.dll" + '\n' +
           'File version:     ' + bfeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
