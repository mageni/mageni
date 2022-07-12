###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Word Remote Code Execution Vulnerabilities (2916605)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903426");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2014-0258", "CVE-2014-0259", "CVE-2014-0260");
  script_bugtraq_id(64726, 64727, 64728);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2014-01-15 09:12:21 +0530 (Wed, 15 Jan 2014)");
  script_name("Microsoft Office Word Remote Code Execution Vulnerabilities (2916605)");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS14-001.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"insight", value:"Multiple flaws are due to error exists when processing specially crafted
  office file.");

  script_tag(name:"affected", value:"Microsoft Word 2013

  Microsoft Word 2003 Service Pack 3 and prior

  Microsoft Word 2007 Service Pack 3  and prior

  Microsoft Word 2010 Service Pack 2 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code, cause memory corruption and compromise the system.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2863866");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2837617");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2863902");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2863901");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2827224");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2863834");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-001");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");

  exit(0);
}

include("secpod_reg.inc");
include("version_func.inc");

winwordVer = get_kb_item("SMB/Office/Word/Version");

## Microsoft Office Word 2003/2007/2010
if(winwordVer && winwordVer =~ "^1[1245]\.")
{
  ## 14 < 14.0.7113.5001, 15 < 15.0.4551.1509
  ## Wwlibcxm.dll file not found on office 2010, as of now its not considered
  ## Wordpia.dll file not found on office 2013, as of now its not considered
  if(version_in_range(version:winwordVer, test_version:"11.0", test_version2:"11.0.8408") ||
     version_in_range(version:winwordVer, test_version:"12.0", test_version2:"12.0.6690.4999") ||
     version_in_range(version:winwordVer, test_version:"14.0", test_version2:"14.0.7113.5000") ||
     version_in_range(version:winwordVer, test_version:"15.0", test_version2:"15.0.4551.1508"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
