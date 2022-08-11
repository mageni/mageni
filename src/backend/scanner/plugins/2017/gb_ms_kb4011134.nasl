###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Viewer Multiple Vulnerabilities (KB4011134)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811697");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2017-8676", "CVE-2017-8682", "CVE-2017-8695");
  script_bugtraq_id(100755, 100772, 100773);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2017-09-14 16:41:31 +0530 (Thu, 14 Sep 2017)");
  script_name("Microsoft Office Word Viewer Multiple Vulnerabilities (KB4011134)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4011134");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,

  - An error in the way Windows Graphics Device Interface (GDI) handles objects
    in memory,

  - An error in the Windows font library which improperly handles specially
    crafted embedded fonts.

  - An error when Windows Uniscribe improperly discloses the contents of its
    memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to retrieve information from a targeted system. By itself, the information
  disclosure does not allow arbitrary code execution. However, it could allow
  arbitrary code to be run if the attacker uses it in combination with another
  vulnerability.");

  script_tag(name:"affected", value:"Microsoft Office Word Viewer");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4011134");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordView/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


if(!wordviewPath = get_kb_item("SMB/Office/WordView/Install/Path")){
 exit(0);
}

if(!dllVer = fetch_file_version(sysPath:wordviewPath, file_name:"gdiplus.dll")){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"11.0.8443"))
{
  report = 'File checked:     ' + wordviewPath + "gdiplus.dll" + '\n' +
           'File version:     ' + dllVer + '\n' +
           'Vulnerable range: Less than 11.0.8443\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
