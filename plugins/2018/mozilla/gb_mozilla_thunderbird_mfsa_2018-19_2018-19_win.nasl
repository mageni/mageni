###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Security Updates(mfsa_2018-19_2018-19)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813815");
  script_version("2019-05-17T10:45:27+0000");
  script_cve_id("CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12361", "CVE-2018-12362",
                "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-5156",
                "CVE-2018-12371", "CVE-2018-12366", "CVE-2018-12367", "CVE-2018-12368",
                "CVE-2018-5187", "CVE-2018-5188");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2018-08-07 11:05:18 +0530 (Tue, 07 Aug 2018)");
  script_name("Mozilla Thunderbird Security Updates(mfsa_2018-19_2018-19)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Memory safety bugs.

  - No warning when opening executable SettingContent-ms files.

  - Timing attack related to PerformanceNavigationTiming.

  - An invalid data handling during QCMS transformations.

  - An integer overflow vulnerability in the Skia library during edge
    builder allocation.

  - A compromised IPC child process can list local filenames.

  - NPAPI plugins, such as Adobe Flash, can send non-simple cross-origin
    requests, bypassing CORS.

  - An use-after-free error when appending DOM nodes.

  - A vulnerability can occur when capturing a media stream when the media
    source type is changed as the capture is occurring.

  - An integer overflow error in SSSE3 scaler.

  - An integer overflow error can occur in the SwizzleData code while calculating
    buffer sizes.

  - An use-after-free error when using focus().

  - A buffer overflow error using computed size of canvas element.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service condition, conduct csrf and timing attacks,
  access private local files and execute arbitrary code.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before 60.0 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 60 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-19");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"60"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"60", install_path:tbPath);
  security_message(data:report);
  exit(0);
}
