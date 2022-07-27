###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Edge Multiple Vulnerabities (3183043)
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
  script_oid("1.3.6.1.4.1.25623.1.0.809042");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2016-3247", "CVE-2016-3291", "CVE-2016-3294", "CVE-2016-3295",
                "CVE-2016-3297", "CVE-2016-3325", "CVE-2016-3330", "CVE-2016-3350",
                "CVE-2016-3351", "CVE-2016-3370", "CVE-2016-3374", "CVE-2016-3377");
  script_bugtraq_id(92828, 92834, 92789, 92830, 92829, 92832, 92807, 92793);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-09-14 08:01:49 +0530 (Wed, 14 Sep 2016)");
  script_name("Microsoft Edge Multiple Vulnerabities (3183043)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-105");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to,

  - The Microsoft Edge improperly handles objects in memory.

  - The Chakra JavaScript engine renders when handling objects in memory in
    Microsoft Edge.

  - The Microsoft Edge improperly handles cross-origin requests.

  - Certain functions improperly handles objects in memory.

  - The PDF Library and Microsoft Browser improperly handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code in the context of the current user, to
  determine the origin of all of the web pages in the affected browser, and to
  obtain information to further compromise a target system.");

  script_tag(name:"affected", value:"Microsoft Windows 10 x32/x64.

  Microsoft Windows 10 Version 1511 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3183043");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/ms16-105");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-105");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

edgePath = smb_get_system32root();
if(!edgePath){
  exit(0);
}

if(!edgeVer = fetch_file_version(sysPath: edgePath, file_name:"edgehtml.dll")){;
  exit(0);
}

if(hotfix_check_sp(win10:1, win10x64:1) > 0)
{
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17113"))
  {
    Vulnerable_range = "Less than 11.0.10240.17113";
    VULN = TRUE ;
  }
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.588"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.588";
    VULN = TRUE ;
  }
}

if(VULN)
{
  report = 'File checked:     ' + edgePath + "\edgehtml.dll"+ '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
