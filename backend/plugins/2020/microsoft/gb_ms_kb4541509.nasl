# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815796");
  script_version("2020-03-11T12:58:09+0000");
  script_cve_id("CVE-2020-0645", "CVE-2020-0684", "CVE-2020-0768", "CVE-2020-0769",
                "CVE-2020-0770", "CVE-2020-0771", "CVE-2020-0772", "CVE-2020-0773",
                "CVE-2020-0774", "CVE-2020-0777", "CVE-2020-0778", "CVE-2020-0779",
                "CVE-2020-0780", "CVE-2020-0781", "CVE-2020-0783", "CVE-2020-0785",
                "CVE-2020-0787", "CVE-2020-0788", "CVE-2020-0791", "CVE-2020-0797",
                "CVE-2020-0799", "CVE-2020-0800", "CVE-2020-0802", "CVE-2020-0803",
                "CVE-2020-0804", "CVE-2020-0806", "CVE-2020-0814", "CVE-2020-0819",
                "CVE-2020-0822", "CVE-2020-0824", "CVE-2020-0830", "CVE-2020-0832",
                "CVE-2020-0833", "CVE-2020-0834", "CVE-2020-0840", "CVE-2020-0842",
                "CVE-2020-0843", "CVE-2020-0844", "CVE-2020-0845", "CVE-2020-0847",
                "CVE-2020-0849", "CVE-2020-0853", "CVE-2020-0857", "CVE-2020-0858",
                "CVE-2020-0859", "CVE-2020-0860", "CVE-2020-0861", "CVE-2020-0864",
                "CVE-2020-0865", "CVE-2020-0866", "CVE-2020-0871", "CVE-2020-0874",
                "CVE-2020-0877", "CVE-2020-0879", "CVE-2020-0880", "CVE-2020-0881",
                "CVE-2020-0882", "CVE-2020-0883", "CVE-2020-0885", "CVE-2020-0887",
                "CVE-2020-0897");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-03-12 11:06:29 +0000 (Thu, 12 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-11 11:25:04 +0530 (Wed, 11 Mar 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4541509)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4541509");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Windows Error Reporting improperly handles memory.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows Graphics Component improperly handles objects in memory.

  - Windows Network Connections Service improperly handles objects in memory.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  For more information about the vulnerabilities refer Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, elevate privilges, disclose sensitive information and
  conduct tampering attacks.");

  script_tag(name:"affected", value:"Windows 8.1 for 32-bit/x64-based systems

  Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4541509");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

sysVer = fetch_file_version(sysPath:sysPath, file_name:"User32.dll");
if(!sysVer){
  exit(0);
}

if(version_is_less(version:sysVer, test_version:"6.3.9600.19653"))
{
  report = report_fixed_ver(file_checked:sysPath + "\User32.dll",
                            file_version:sysVer, vulnerable_range:"Less than 6.3.9600.19653");
  security_message(data:report);
  exit(0);
}
exit(99);
