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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.01");
  script_cve_id("CVE-2021-4140", "CVE-2022-22736", "CVE-2022-22737", "CVE-2022-22738", "CVE-2022-22739", "CVE-2022-22740", "CVE-2022-22741", "CVE-2022-22742", "CVE-2022-22743", "CVE-2022-22744", "CVE-2022-22745", "CVE-2022-22746", "CVE-2022-22747", "CVE-2022-22748", "CVE-2022-22749", "CVE-2022-22750", "CVE-2022-22751", "CVE-2022-22752", "CVE-2022-22763");
  script_tag(name:"creation_date", value:"2022-02-09 13:04:21 +0000 (Wed, 09 Feb 2022)");
  script_version("2022-02-09T13:04:21+0000");
  script_tag(name:"last_modification", value:"2022-02-10 11:02:19 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-02-09 13:04:21 +0000 (Wed, 09 Feb 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1664149%2C1737816%2C1739366%2C1740274%2C1740797%2C1741201%2C1741869%2C1743221%2C1743515%2C1745373%2C1746011");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1741210%2C1742770");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1566608");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1705094");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1705211");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1735028");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1735071");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1735856");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1737252");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1739220");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1739923");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1740389");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1740534");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1742334");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1742382");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1742692");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1744158");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1745874");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1746720");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-22746: Calling into reportValidity could have lead to fullscreen window spoof
A race condition could have allowed bypassing the fullscreen notification which could have lead to a fullscreen window spoof being unnoticed.This bug only affects Firefox for Windows. Other operating systems are unaffected.

CVE-2022-22743: Browser window spoof using fullscreen mode
When navigating from inside an iframe while requesting fullscreen access, an attacker-controlled tab could have made the browser unable to leave fullscreen mode.

CVE-2022-22742: Out-of-bounds memory access when inserting text in edit mode
When inserting text while in edit mode, some characters might have lead to out-of-bounds memory access causing a potentially exploitable crash.

CVE-2022-22741: Browser window spoof using fullscreen mode
When resizing a popup while requesting fullscreen access, the popup would have become unable to leave fullscreen mode.

CVE-2022-22740: Use-after-free of ChannelEventQueue::mOwner
Certain network request objects were freed too early when releasing a network request handle. This could have lead to a use-after-free causing a potentially exploitable crash.

CVE-2022-22738: Heap-buffer-overflow in blendGaussianBlur
Applying a CSS filter effect could have accessed out of bounds memory. This could have lead to a heap-buffer-overflow causing a potentially exploitable crash.

CVE-2022-22737: Race condition when playing audio files
Constructing audio sinks could have lead to a race condition when playing audio files and closing windows. This could have lead to a use-after-free causing a potentially exploitable crash.

CVE-2021-4140: Iframe sandbox bypass with XSLT
It was possible to construct specific XSLT markup that would be able to bypass an iframe sandbox.

CVE-2022-22750: IPC passing of resource handles could have lead to sandbox bypass
By generally accepting and passing resource handles across processes, a compromised content process might have confused higher privileged processes to interact with handles that the unprivileged process should not have access to.This bug only affects Firefox for Windows and MacOS. Other operating systems are unaffected.

CVE-2022-22749: Lack of URL restrictions when scanning QR codes
When scanning QR codes, Firefox for Android would have allowed navigation to some URLs that do not point to web content.This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2022-22748: Spoofed origin on external protocol launch dialog
Malicious websites could have confused Firefox into showing the wrong origin when asking to launch a program and handling an external URL protocol.

CVE-2022-22745: Leaking cross-origin URLs through securitypolicyviolation event
Securitypolicyviolation events could have leaked cross-origin information for frame-ancestors violations

CVE-2022-22744: The 'Copy as curl' feature in DevTools did not ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 96.");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the reference(s) for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "96")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "96", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
