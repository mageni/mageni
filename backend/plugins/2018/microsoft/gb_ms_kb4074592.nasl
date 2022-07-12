###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4074592)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812762");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2018-0742", "CVE-2018-0756", "CVE-2018-0757", "CVE-2018-0763",
                "CVE-2018-0771", "CVE-2018-0809", "CVE-2018-0820", "CVE-2018-0821",
                "CVE-2018-0822", "CVE-2018-0825", "CVE-2018-0826", "CVE-2018-0827",
                "CVE-2018-0829", "CVE-2018-0830", "CVE-2018-0831", "CVE-2018-0832",
                "CVE-2018-0834", "CVE-2018-0835", "CVE-2018-0836", "CVE-2018-0837",
                "CVE-2018-0838", "CVE-2018-0839", "CVE-2018-0840", "CVE-2018-0842",
                "CVE-2018-0844", "CVE-2018-0846", "CVE-2018-0847", "CVE-2018-0856",
                "CVE-2018-0857", "CVE-2018-0859", "CVE-2018-0860", "CVE-2018-0861",
                "CVE-2018-0866");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-02-14 09:33:29 +0530 (Wed, 14 Feb 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4074592)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4074592");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - The scripting engine improperly handles objects in memory in Microsoft
    browsers.

  - The windows kernel fails to properly handle objects in memory.

  - The windows Common Log File System (CLFS) driver improperly handles
    objects in memory.

  - The VBScript improperly discloses the contents of its memory.

  - The scripting engine improperly handles objects in memory in Microsoft Edge.

  - The scripting engine improperly handles objects in memory in Internet Explorer.

  - The storage Services improperly handles objects in memory.

  - The NTFS improperly handles objects.

  - The AppContainer improperly implements constrained impersonation.

  - Microsoft has deprecated the Document Signing functionality in XPS Viewer.

  - Microsoft Edge improperly handles requests of different origins.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to gain the same
  user rights as the current user, run arbitrary code in kernel mode, run
  processes in an elevated context, circumvent a User Mode Code Integrity
  (UMCI) policy on the machine, spoof content, perform phishing attacks, or
  otherwise manipulate content of a document, force the browser to send data
  that would otherwise be restricted and retrieve the memory address of a
  kernel object.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1703 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4074592");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.15063.0", test_version2:"11.0.15063.908"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.15063.0 - 11.0.15063.908");
  security_message(data:report);
  exit(0);
}
exit(0);
