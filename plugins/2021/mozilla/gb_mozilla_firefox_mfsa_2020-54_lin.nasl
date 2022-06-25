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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.54");
  script_cve_id("CVE-2020-16042", "CVE-2020-26971", "CVE-2020-26972", "CVE-2020-26973", "CVE-2020-26974", "CVE-2020-26975", "CVE-2020-26976", "CVE-2020-26977", "CVE-2020-26978", "CVE-2020-26979", "CVE-2020-35111", "CVE-2020-35112", "CVE-2020-35113", "CVE-2020-35114");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-11 18:39:00 +0000 (Mon, 11 Jan 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-54) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-54");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-54/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1607449%2C1640416%2C1656459%2C1669914%2C1673567");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1641287%2C1673299");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1664831%2C1673589");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1657916");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1661071");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1661365");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1663466");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1671382");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1674343");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1676311");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1677047");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1679003");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1680084");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1681022");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-16042: Operations on a BigInt could have caused uninitialized memory to be exposed
When a BigInt was right-shifted the backing store was not properly cleared, allowing uninitialized memory to be read.

CVE-2020-26971: Heap buffer overflow in WebGL
Certain blit values provided by the user were not properly constrained leading to a heap buffer overflow on some video drivers.

CVE-2020-26972: Use-After-Free in WebGL
The lifecycle of IPC Actors allows managed actors to outlive their manager actors, and the former must ensure that they are not attempting to use a dead actor they have a reference to. Such a check was omitted in WebGL, resulting in a use-after-free and a potentially exploitable crash.

CVE-2020-26973: CSS Sanitizer performed incorrect sanitization
Certain input to the CSS Sanitizer confused it, resulting in incorrect components being removed. This could have been used as a sanitizer bypass.

CVE-2020-26974: Incorrect cast of StyleGenericFlexBasis resulted in a heap use-after-free
When flex-basis was used on a table wrapper, a StyleGenericFlexBasis object could have been incorrectly cast to the wrong type. This resulted in a heap user-after-free, memory corruption, and a potentially exploitable crash.

CVE-2020-26975: Malicious applications on Android could have induced Firefox for Android into sending arbitrary attacker-specified headers
When a malicious application installed on the user's device broadcast an Intent to Firefox for Android, arbitrary headers could have been specified, leading to attacks such as abusing ambient authority or session fixation. This was resolved by only allowing certain safe-listed headers.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2020-26976: HTTPS pages could have been intercepted by a registered service worker when they should not have been
When a HTTPS pages was embedded in a HTTP page, and there was a service worker registered for the former, the service worker could have intercepted the request for the secure page despite the iframe not being a secure context due to the (insecure) framing.

CVE-2020-26977: URL spoofing via unresponsive port in Firefox for Android
By attempting to connect a website using an unresponsive port, an attacker could have controlled the content of a tab while the URL bar displayed the original domain. Note: This issue only affects Firefox for Android. Other operating systems are unaffected.

CVE-2020-26978: Internal network hosts could have been probed by a malicious webpage
Using techniques that built on the slipstream research, a malicious webpage could have exposed both an internal network's hosts as well as services running on the user's local machine.

CVE-2020-26979: When entering an address in the address or search bars, a website could have redirected the user before they were navigated to the intended url
When a user typed a URL ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 84.");

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

if (version_is_less(version: version, test_version: "84")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "84", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
