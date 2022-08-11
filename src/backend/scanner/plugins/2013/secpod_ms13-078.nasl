###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft FrontPage Information Disclosure Vulnerability (2825621)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
CPE = "cpe:/a:microsoft:frontpage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903321");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2013-3137");
  script_bugtraq_id(62185);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2013-09-11 11:12:46 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft FrontPage Information Disclosure Vulnerability (2825621)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS13-078.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"insight", value:"Flaw is due to an an unspecified information disclosure vulnerability.");
  script_tag(name:"affected", value:"Microsoft FrontPage 2003 Service Pack 3");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose the contents
of a file on a target system.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2825621");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS13-078");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_frontpage_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Microsoft/FrontPage/Ver");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-078");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

appPath = get_app_location(cpe:CPE);

if(appPath && "Unable to find the install" >!< appPath)
{
  pageVer = fetch_file_version(sysPath: appPath, file_name:"Frontpg.exe");
  if(!pageVer){
    exit(0);
  }

  if(version_in_range(version:pageVer, test_version:"11.0", test_version2:"11.0.8338"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
