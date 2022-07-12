###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4038782)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811820");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-0161", "CVE-2017-11764", "CVE-2017-8719", "CVE-2017-8720",
                "CVE-2017-8723", "CVE-2017-8728", "CVE-2017-11766", "CVE-2017-8628",
                "CVE-2017-8643", "CVE-2017-8731", "CVE-2017-8733", "CVE-2017-8734",
                "CVE-2017-8735", "CVE-2017-8736", "CVE-2017-8649", "CVE-2017-8660",
                "CVE-2017-8675", "CVE-2017-8676", "CVE-2017-8737", "CVE-2017-8738",
                "CVE-2017-8741", "CVE-2017-8678", "CVE-2017-8679", "CVE-2017-8748",
                "CVE-2017-8749", "CVE-2017-8750", "CVE-2017-8752", "CVE-2017-8753",
                "CVE-2017-8754", "CVE-2017-8681", "CVE-2017-8682", "CVE-2017-8755",
                "CVE-2017-8756", "CVE-2017-8757", "CVE-2017-8759", "CVE-2017-8683",
                "CVE-2017-8686", "CVE-2017-9417", "CVE-2017-8687", "CVE-2017-8688",
                "CVE-2017-8692", "CVE-2017-8695", "CVE-2017-8699", "CVE-2017-8702",
                "CVE-2017-8704", "CVE-2017-8706", "CVE-2017-8707", "CVE-2017-8708",
                "CVE-2017-8709", "CVE-2017-8711", "CVE-2017-8712", "CVE-2017-8713",
                "CVE-2017-8714", "CVE-2017-8677", "CVE-2017-8746", "CVE-2017-8747");

  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 11:47:09 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4038782)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4038782");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This update includes quality improvements.

  - Windows Error Reporting doesn't clean up temporary files when there is a
    redirection on a folder.

  - Internet Explorer 11's navigation bar with search box.

  - Internet Explorer where undo is broken if character conversion is canceled
    using IME.

  - Internet Explorer where graphics render incorrectly.

  - Windows clients receive a 0xc0000005 ACCESS_VIOLATION error when trying to
    install drivers.

  - A race condition may cause a blue screen on the server when Windows Server
    uses IPSec.

  - Internet Explorer sometimes fails to display webpages correctly when a user
    installs Windows with the CopyProfile unattend setting.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker to run arbitrary code, conduct spoofing attack, escalate privileges,
  and also to obtian sensitive information.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1607 x32/x64

  Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4038782");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
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

if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.1714"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.14393.0 - 11.0.14393.1714\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
