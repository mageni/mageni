# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815082");
  script_version("2019-05-24T13:25:42+0000");
  script_cve_id("CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818",
                "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-7317", "CVE-2019-11691",
                "CVE-2019-11692", "CVE-2019-9797", "CVE-2018-18511", "CVE-2019-11694",
                "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-9800");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-24 13:25:42 +0000 (Fri, 24 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-24 12:21:27 +0530 (Fri, 24 May 2019)");
  script_name("Mozilla Thunderbird Security Updates( mfsa_2019-13_2019-15 )-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An out-of-bounds read error in Skia.

  - Theft of user history data through drag and drop of hyperlinks to and from bookmarks.

  - An uninitialized memory memory leakage in Windows.

  - Cross-origin theft of images with ImageBitmapRenderingContext and createImageBitmap.

  - Multiple use-after-free errors in png_image_free of libpng library,
    event listener manager, XMLHttpRequest, chrome event handler and crash generation server.

  - Compartment mismatch with fetch API.

  - Stealing of cross-domain images using canvas.

  - Type confusion with object groups and UnboxedObjects.

  - A timing attack vulnerability related to not disabling hyperthreading.

  - Memory safety bugs");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  conduct timing attack, security bypass, execute arbitrary code denial of service.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  60.7 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60.7
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-15/");
  script_xref(name:"URL", value:"https://www.thunderbird.net");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"60.7"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"60.7", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
exit(0);
