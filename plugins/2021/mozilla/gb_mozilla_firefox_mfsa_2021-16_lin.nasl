# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.16");
  script_cve_id("CVE-2021-23994", "CVE-2021-23995", "CVE-2021-23996", "CVE-2021-23997", "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-24000", "CVE-2021-24001", "CVE-2021-24002", "CVE-2021-29944", "CVE-2021-29945", "CVE-2021-29946", "CVE-2021-29947");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 14:55:00 +0000 (Fri, 02 Jul 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-16) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-16");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-16/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1651449%2C1674142%2C1693476%2C1696886%2C1700091");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1667456");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1691153");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1694698");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1694727");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1697604");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1698503");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1699077");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1699835");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1700690");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1701834");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1701942");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1702374");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-23994: Out of bound write due to lazy initialization
A WebGL framebuffer was not initialized early enough, resulting in memory corruption and an out of bound write.

CVE-2021-23995: Use-after-free in Responsive Design Mode
When Responsive Design Mode was enabled, it used references to objects that were previously freed. We presume that with enough effort this could have been exploited to run arbitrary code.

CVE-2021-23996: Content rendered outside of webpage viewport
By utilizing 3D CSS in conjunction with Javascript, content could have been rendered outside the webpage's viewport, resulting in a spoofing attack that could have been used for phishing or other attacks on a user.

CVE-2021-23997: Use-after-free when freeing fonts from cache
Due to unexpected data type conversions, a use-after-free could have occurred when interacting with the font cache. We presume that with enough effort this could have been exploited to run arbitrary code.

CVE-2021-23998: Secure Lock icon could have been spoofed
Through complicated navigations with new windows, an HTTP page could have inherited a secure lock icon from an HTTPS page.

CVE-2021-23999: Blob URLs may have been granted additional privileges
If a Blob URL was loaded through some unusual user interaction, it could have been loaded by the System Principal and granted additional privileges that should not be granted to web content.

CVE-2021-24000: requestPointerLock() could be applied to a tab different from the visible tab
A race condition with requestPointerLock() and setTimeout() could have resulted in a user interacting with one tab when they believed they were on a separate tab. In conjunction with certain elements (such as <input type='file'>) this could have led to an attack where a user was confused about the origin of the webpage and potentially disclosed information they did not intend to.

CVE-2021-24001: Testing code could have enabled session history manipulations by a compromised content process
A compromised content process could have performed session history manipulations it should not have been able to due to testing infrastructure that was not restricted to testing-only configurations.

CVE-2021-24002: Arbitrary FTP command execution on FTP servers using an encoded URL
When a user clicked on an FTP URL containing encoded newline characters (%0A and %0D), the newlines would have been interpreted as such and allowed arbitrary commands to be sent to the FTP server.

CVE-2021-29945: Incorrect size computation in WebAssembly JIT could lead to null-reads
The WebAssembly JIT could miscalculate the size of a return type, which could lead to a null read and result in a crash.
Note: This issue only affected x86-32 platforms. Other platforms are unaffected.

CVE-2021-29944: HTML injection vulnerability in Firefox for Android's Reader View
Lack of escaping allowed HTML injection when a webpage was viewed in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 88.");

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

if (version_is_less(version: version, test_version: "88")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "88", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
