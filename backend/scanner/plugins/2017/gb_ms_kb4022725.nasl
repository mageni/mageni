###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4022725)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811167");
  script_version("2019-05-03T13:51:56+0000");
  script_cve_id("CVE-2017-8474", "CVE-2017-8524", "CVE-2017-8527", "CVE-2017-8475",
                "CVE-2017-8476", "CVE-2017-8529", "CVE-2017-8530", "CVE-2017-0282",
                "CVE-2017-0283", "CVE-2017-8477", "CVE-2017-8478", "CVE-2017-8531",
                "CVE-2017-8532", "CVE-2017-0285", "CVE-2017-8479", "CVE-2017-8480",
                "CVE-2017-8533", "CVE-2017-8543", "CVE-2017-0287", "CVE-2017-0288",
                "CVE-2017-8481", "CVE-2017-8482", "CVE-2017-8544", "CVE-2017-8547",
                "CVE-2017-8548", "CVE-2017-8549", "CVE-2017-0289", "CVE-2017-0291",
                "CVE-2017-8483", "CVE-2017-8484", "CVE-2017-8555", "CVE-2017-0292",
                "CVE-2017-0294", "CVE-2017-0295", "CVE-2017-8485", "CVE-2017-8489",
                "CVE-2017-0296", "CVE-2017-0297", "CVE-2017-0298", "CVE-2017-8490",
                "CVE-2017-8491", "CVE-2017-0299", "CVE-2017-0300", "CVE-2017-8492",
                "CVE-2017-8493", "CVE-2017-8498", "CVE-2017-8499", "CVE-2017-8504",
                "CVE-2017-8460", "CVE-2017-8462", "CVE-2017-8470", "CVE-2017-8471",
                "CVE-2017-8520", "CVE-2017-8521", "CVE-2017-8522", "CVE-2017-8523",
                "CVE-2017-8464", "CVE-2017-8465", "CVE-2017-8515", "CVE-2017-8517",
		        "CVE-2017-8554", "CVE-2017-8575", "CVE-2017-8518");
  script_bugtraq_id(98902, 98930, 98933, 98853, 98903, 98953, 98863, 98885, 98920,
		    98854, 98845, 98819, 98820, 98914, 98856, 98857, 98821, 98824,
                    98922, 98923, 98862, 98858, 98826, 98932, 98954, 98955, 98929,
                    98835, 98859, 98847, 98956, 98836, 98837, 98904, 98860, 98865,
                    98839, 98840, 98867, 98869, 98884, 98901, 98870, 98850, 98886,
                    98883, 98892, 98887, 98900, 98848, 98849, 98925, 98926, 98928,
                    98818, 98843, 98833, 98895);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 13:51:56 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 13:30:05 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4022725)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4022725");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws are due to,

  - The error with slow firewall operations that sometimes results in
    timeouts of Surface Hub's cleanup operation.

  - An issue with a race condition that prevents Cortana cross-device
    notification reply from working. Users will not be able to use the
    remote toast activation feature set.

  - An issue with the Privacy Separator feature of a Wireless Access Point
    does not block communication between wireless devices on local subnets.

  - Microsoft Edge improperly accesses objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code in the context of the current user,
  gain the same user rights as the current user and to take control of
  an affected system.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1703 x32/x64

  Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4022725");
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

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"Edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.15063.0", test_version2:"11.0.15063.412"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.15063.0 - 11.0.15063.412\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
