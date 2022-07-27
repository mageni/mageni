###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Lync Attendee Multiple Remote Code Execution Vulnerabilities (KB4025866 and KB4025867)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811327");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8676", "CVE-2017-8695", "CVE-2017-8696");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 15:57:23 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Lync Attendee Multiple Remote Code Execution Vulnerabilities (KB4025866 and KB4025867)");

  script_tag(name:"summary", value:"This host is missing a critical security
  updates according to Microsoft KB4025866 and KB4025867.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to the windows font
  library which improperly handles specially crafted embedded fonts.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Lync Attendee 2010");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025867");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025866");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_lync_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Lync/Attendee/Ver", "MS/Lync/Attendee/path");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025867");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_smb_func.inc");
include("version_func.inc");

## For Microsoft Lync 2010 Attendee (admin level install)
## For Microsoft Lync 2010 Attendee (user level install)
lyncPath = get_kb_item("MS/Lync/Attendee/path");
if(lyncPath)
{
  dllVer = fetch_file_version(sysPath:lyncPath, file_name:"Rtmpltfm.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"4.0", test_version2:"4.0.7577.4539"))
    {

      report = 'File checked:     ' + lyncPath + "Rtmpltfm.dll" + '\n' +
               'File version:     ' + dllVer  + '\n' +
               'Vulnerable range: 4.0 - 4.0.7577.4539' + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
