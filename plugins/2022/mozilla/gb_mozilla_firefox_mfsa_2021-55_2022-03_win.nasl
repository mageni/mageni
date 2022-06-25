# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819951");
  script_version("2022-01-20T06:32:54+0000");
  script_cve_id("CVE-2022-22746", "CVE-2022-22743", "CVE-2022-22742", "CVE-2022-22741",
                "CVE-2022-22740", "CVE-2022-22738", "CVE-2022-22737", "CVE-2021-4140",
                "CVE-2022-22750", "CVE-2022-22752", "CVE-2022-22748", "CVE-2022-22745",
                "CVE-2022-22744", "CVE-2022-22747", "CVE-2022-22736", "CVE-2022-22739",
                "CVE-2022-22751");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-01-20 06:32:54 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-14 15:22:43 +0530 (Fri, 14 Jan 2022)");
  script_name("Mozilla Firefox Security Update(mfsa_2021-55_2022-03)-Windows");

  script_tag(name:"summary", value:"Mozilla Firefox ESR is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Calling into reportValidity could have lead to fullscreen window spoof.

  - Browser window spoof using fullscreen mode.

  - Out-of-bounds memory access when inserting text in edit mode.

  - Use-after-free of ChannelEventQueue::mOwner.

  - Heap-buffer-overflow in blendGaussianBlur.

  - Race condition when playing audio files.

  - Iframe sandbox bypass with XSLT.

  - IPC passing of resource handles could have lead to sandbox bypass.

  - Spoofed origin on external protocol launch dialog.

  - Leaking cross-origin URLs through securitypolicyviolation event.

  - The 'Copy as curl' feature in DevTools did not fully escape
    website-controlled data, potentially leading to command injection.

  - Crash when handling empty pkcs7 sequence.

  - Potential local privilege escalation when loading modules from the install directory.

  - Missing throttling on external protocol launch dialog.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct spoofing, denail of service, execute arbitrary commands
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  96 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 96
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-01/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"96"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"96", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
