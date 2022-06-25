###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft OneNote Remote Code Execution Vulnerability (2977201)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804809");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-2815");
  script_bugtraq_id(69098);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-08-13 13:20:09 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft OneNote Remote Code Execution Vulnerability (2977201)");


  script_tag(name:"summary", value:"This host is missing an important security update according to
Microsoft Bulletin MS14-048");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code and
compromise a user's system.");
  script_tag(name:"affected", value:"Microsoft OneNote 2007 Service Pack 3");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2982791");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2976897");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-048");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_mandatory_keys("MS/Office/OneNote/Ver");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-048");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

noteVer = get_app_version(cpe:CPE);

if(noteVer && noteVer =~ "^12.*")
{
  if(version_in_range(version:noteVer, test_version:"12.0", test_version2:"12.0.6650.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
