###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Viewer Multiple Remote Code Execution Vulnerabilities (3177393)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807874");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2016-3301", "CVE-2016-3303", "CVE-2016-3304");
  script_bugtraq_id(92288, 92301, 92302);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-08-10 15:00:54 +0530 (Wed, 10 Aug 2016)");
  script_name("Microsoft Office Word Viewer Multiple Remote Code Execution Vulnerabilities (3177393)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-097.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the windows font
  library which improperly handles specially crafted embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Word Viewer");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3115481");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS16-097");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/Office/WordView/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path");
if(!wordviewPath){
  exit(0);
}

if(wordviewPath)
{
  wordviewVer = fetch_file_version(sysPath:wordviewPath, file_name:"gdiplus.dll");

  if(wordviewVer)
  {
    ## gdipluss.dll will update for https://support.microsoft.com/en-us/kb/3115481
    if(version_in_range(version:wordviewVer, test_version:"11.0", test_version2:"11.0.8431"))
    {
      report = 'File checked:     ' + wordviewPath + "/gdiplus.dll" + '\n' +
               'File version:     ' + wordviewVer  + '\n' +
               'Vulnerable range: 11.0 - 11.0.8431 \n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
