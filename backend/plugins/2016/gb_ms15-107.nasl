###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Edge Multiple Information Disclosure Vulnerabilities (3096448)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807024");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2015-6057", "CVE-2015-6058");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-01-06 15:54:16 +0530 (Wed, 06 Jan 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Edge Multiple Information Disclosure Vulnerabilities (3096448)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-107.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Microsoft Edge improperly discloses the contents of its memory.

  - Cross-site scripting (XSS) filter bypass exists in the way that Microsoft
    Edge disables an HTML attribute in otherwise appropriately filtered HTTP
    response data. The bypass could allow initially disabled scripts to run in
    the wrong security context.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information from process memory and to bypass a
  cross-site scripting (XSS) protection mechanism leading to information
  disclosure.");

  script_tag(name:"affected", value:"Microsoft Edge on Windows 10 x32/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3096448");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-107");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Edge/Installed");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"11.0.10240.16549"))
  {
    report = 'File checked:     ' + sysPath + "\edgehtml.dll" + '\n' +
             'File version:     ' + dllVer  + '\n' +
             'Vulnerable range: Less than 11.0.10240.16549\n' ;
    security_message(data:report);
    exit(0);
  }
}
