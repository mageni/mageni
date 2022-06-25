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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.50");
  script_cve_id("CVE-2020-15999", "CVE-2020-16012", "CVE-2020-26951", "CVE-2020-26952", "CVE-2020-26953", "CVE-2020-26954", "CVE-2020-26955", "CVE-2020-26956", "CVE-2020-26957", "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26961", "CVE-2020-26962", "CVE-2020-26963", "CVE-2020-26964", "CVE-2020-26965", "CVE-2020-26966", "CVE-2020-26967", "CVE-2020-26968", "CVE-2020-26969");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-09 19:08:00 +0000 (Wed, 09 Dec 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-50) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-50");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-50/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1551615%2C1607762%2C1656697%2C1657739%2C1660236%2C1667912%2C1671479%2C1671923");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1623920%2C1651705%2C1667872%2C1668876");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1314912");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1642028");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1656741");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1657026");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1658865");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1661617");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1663261");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1663571");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1665820");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1666300");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1667113");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1667179");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1667685");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1669355");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1669466");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1670358");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1672223");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1672528");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=610997");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-26951: Parsing mismatches could confuse and bypass security sanitizer for chrome privileged code
A parsing and event loading mismatch in Firefox's SVG code could have allowed load events to fire, even after sanitization. An attacker already capable of exploiting an XSS vulnerability in privileged internal pages could have used this attack to bypass our built-in sanitizer.

CVE-2020-26952: Out of memory handling of JITed, inlined functions could lead to a memory corruption
Incorrect bookkeeping of functions inlined during JIT compilation could have led to memory corruption and a potentially exploitable crash when handling out-of-memory errors.

CVE-2020-16012: Variable time processing of cross-origin images during drawImage calls
When drawing a transparent image on top of an unknown cross-origin image, the Skia library drawImage function took a variable amount of time depending on the content of the underlying image. This resulted in potential cross-origin information exposure of image content through timing side-channel attacks.

CVE-2020-26953: Fullscreen could be enabled without displaying the security UI
It was possible to cause the browser to enter fullscreen mode without displaying the security UI, thus making it possible to attempt a phishing attack or otherwise confuse the user.

CVE-2020-26954: Local spoofing of web manifests for arbitrary pages in Firefox for Android
When accepting a malicious intent from other installed apps, Firefox for Android accepted manifests from arbitrary file paths and allowed declaring webapp manifests for other origins. This could be used to gain fullscreen access for UI spoofing and could also lead to cross-origin attacks on targeted websites.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2020-26955: Cookies set during file downloads are shared between normal and Private Browsing Mode in Firefox for Android
When a user downloaded a file in Firefox for Android, if a cookie is set, it would have been re-sent during a subsequent file download operation on the same domain, regardless of whether the original and subsequent request were in private and non-private browsing modes.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2020-26956: XSS through paste (manual and clipboard API)
In some cases, removing HTML elements during sanitization would keep existing SVG event handlers and therefore lead to XSS.

CVE-2020-26957: OneCRL was not working in Firefox for Android
OneCRL was non-functional in the new Firefox for Android due to a missing service initialization. This could result in a failure to enforce some certificate revocations.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2020-26958: Requests intercepted through ServiceWorkers lacked MIME type restrictions
Firefox did not block ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 83.");

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

if (version_is_less(version: version, test_version: "83")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "83", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
