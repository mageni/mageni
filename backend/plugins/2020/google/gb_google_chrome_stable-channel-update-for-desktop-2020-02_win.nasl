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


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815757");
  script_version("2020-02-06T07:28:53+0000");
  script_cve_id("CVE-2020-6381", "CVE-2020-6382", "CVE-2019-18197", "CVE-2019-19926",
                "CVE-2020-6385", "CVE-2019-19925", "CVE-2020-6387", "CVE-2020-6388",
                "CVE-2020-6389", "CVE-2020-6390", "CVE-2020-6391", "CVE-2020-6392",
                "CVE-2020-6393", "CVE-2020-6394", "CVE-2020-6395", "CVE-2020-6396",
                "CVE-2020-6397", "CVE-2020-6398", "CVE-2020-6399", "CVE-2020-6400",
                "CVE-2020-6401", "CVE-2020-6402", "CVE-2020-6403", "CVE-2020-6404",
                "CVE-2020-6405", "CVE-2020-6406", "CVE-2019-19923", "CVE-2020-6408",
                "CVE-2020-6409", "CVE-2020-6410", "CVE-2020-6411", "CVE-2020-6412",
                "CVE-2020-6413", "CVE-2020-6414", "CVE-2020-6415", "CVE-2020-6416",
                "CVE-2020-6417", "CVE-2019-19880");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-02-06 07:28:53 +0000 (Thu, 06 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-05 11:51:03 +0530 (Wed, 05 Feb 2020)");
  script_name("Google Chrome Security Updates(stable-channel-update-for-desktop-2020-02)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An integer overflow issue in JavaScript.

  - A type confusion issue in JavaScript.

  - Multiple vulnerabilities in XML and SQLite.

  - Insufficient policy enforcement issue in storage.

  - An out of bounds write issue in WebRTC.

  - An out of bounds memory access issue in WebAudio.

  - A use after free issue in audio.

  - For more information refer the references.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  execute arbitrary code, read sensitive information, bypass security restrictions,
  perform unauthorized actions or cause denial of service conditions.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 80.0.3987.87 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  80.0.3987.87 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2020/02/stable-channel-update-for-desktop.html?m=1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
chr_ver = infos['version'];
chr_path = infos['location'];

if(version_is_less(version:chr_ver, test_version:"80.0.3987.87"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"80.0.3987.87", install_path:chr_path);
  security_message(data:report);
  exit(0);
}
exit(99);
