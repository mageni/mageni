# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816728");
  script_version("2020-04-01T06:03:08+0000");
  script_cve_id("CVE-2020-3808");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-01 10:03:03 +0000 (Wed, 01 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-03-27 18:27:46 +0530 (Fri, 27 Mar 2020)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Creative Cloud Security Update APSB20-11 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Adobe Creative
  cloud and is prone to an arbitrary file deletion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Time-of-check to
  time-of-use (TOCTOU) race condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to delete arbitrary files on the target system.");

  script_tag(name:"affected", value:"Adobe Creative Cloud 5.0 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  5.1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb20-11.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/creative-cloud");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_macosx.nasl");
  script_mandatory_keys("AdobeCreativeCloud/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos['version'];
cloudPath = infos['location'];

if(version_is_less(version:cloudVer, test_version:"5.1"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"5.1", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);
