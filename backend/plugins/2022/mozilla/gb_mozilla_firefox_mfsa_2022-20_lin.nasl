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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.20");
  script_cve_id("CVE-2022-1919", "CVE-2022-31736", "CVE-2022-31737", "CVE-2022-31738", "CVE-2022-31739", "CVE-2022-31740", "CVE-2022-31741", "CVE-2022-31742", "CVE-2022-31743", "CVE-2022-31744", "CVE-2022-31745", "CVE-2022-31747", "CVE-2022-31748");
  script_tag(name:"creation_date", value:"2022-06-01 07:46:07 +0000 (Wed, 01 Jun 2022)");
  script_version("2022-06-01T07:46:07+0000");
  script_tag(name:"last_modification", value:"2022-06-02 06:59:17 +0000 (Thu, 02 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-06-01 07:46:07 +0000 (Wed, 01 Jun 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-20) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-20");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-20/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1713773%2C1762201%2C1762469%2C1762770%2C1764878%2C1765226%2C1765782%2C1765973%2C1767177%2C1767181%2C1768232%2C1768251%2C1769869");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1760765%2C1765610%2C1766283%2C1767365%2C1768559%2C1768734");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1730434");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1735923");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1743767");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1747388");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1756388");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1757604");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1760944");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1761275");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1765049");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1766806");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1767590");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-31736: Cross-Origin resource's length leaked
A malicious website could have learned the size of a cross-origin resource that supported Range requests.

CVE-2022-31737: Heap buffer overflow in WebGL
A malicious webpage could have caused an out-of-bounds write in WebGL, leading to memory corruption and a potentially exploitable crash.

CVE-2022-31738: Browser window spoof using fullscreen mode
When exiting fullscreen mode, an iframe could have confused the browser about the current state of fullscreen, resulting in potential user confusion or spoofing attacks.

CVE-2022-31739: Attacker-influenced path traversal when saving downloaded files
When downloading files on Windows, the % character was not escaped, which could have lead to a download incorrectly being saved to attacker-influenced paths that used variables such as %HOMEPATH% or %APPDATA%.This bug only affects Firefox for Windows. Other operating systems are unaffected.

CVE-2022-31740: Register allocation problem in WASM on arm64
On arm64, WASM code could have resulted in incorrect assembly generation leading to a register allocation problem, and a potentially exploitable crash.

CVE-2022-31741: Uninitialized variable leads to invalid memory read
A crafted CMS message could have been processed incorrectly, leading to an invalid memory read, and potentially further memory corruption.

CVE-2022-31742: Querying a WebAuthn token with a large number of allowCredential entries may have leaked cross-origin information
An attacker could have exploited a timing attack by sending a large number of allowCredential entries and detecting the difference between invalid key handles and cross-origin key handles. This could have led to cross-origin account linking in violation of WebAuthn goals.

CVE-2022-31743: HTML Parsing incorrectly ended HTML comments prematurely
Firefox's HTML parser did not correctly interpret HTML comment tags, resulting in an incongruity with other browsers. This could have been used to escape HTML comments on pages that put user-controlled data in them.

CVE-2022-31744: CSP bypass enabling stylesheet injection
An attacker could have injected CSS into stylesheets accessible via internal URIs, such as resource:, and in doing so bypass a page's Content Security Policy.

CVE-2022-31745: Incorrect Assertion caused by unoptimized array shift operations
If array shift operations are not used, the Garbage Collector may have become confused about valid objects.

CVE-2022-1919: Memory Corruption when manipulating webp images
An attacker could have caused an uninitialized variable on the stack to be mistakenly freed, causing a potentially exploitable crash.

CVE-2022-31747: Memory safety bugs fixed in Firefox 101 and Firefox ESR 91.10
Mozilla developers Andrew McCreight, Nicolas B. Pierron, and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 100 and Firefox ESR 91.9. Some of these ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 101.");

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

if (version_is_less(version: version, test_version: "101")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "101", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
