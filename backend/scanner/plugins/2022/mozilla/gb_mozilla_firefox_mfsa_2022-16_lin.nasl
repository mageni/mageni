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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.16");
  script_cve_id("CVE-2022-29909", "CVE-2022-29910", "CVE-2022-29911", "CVE-2022-29912", "CVE-2022-29914", "CVE-2022-29915", "CVE-2022-29916", "CVE-2022-29917", "CVE-2022-29918");
  script_tag(name:"creation_date", value:"2022-05-04 07:49:35 +0000 (Wed, 04 May 2022)");
  script_version("2022-05-04T07:50:24+0000");
  script_tag(name:"last_modification", value:"2022-05-05 10:20:08 +0000 (Thu, 05 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-05-04 07:49:35 +0000 (Wed, 04 May 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-16) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-16");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-16/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1684739%2C1706441%2C1753298%2C1762614%2C1762620%2C1764778");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1744043%2C1747178%2C1753535%2C1754017%2C1755847%2C1756172%2C1757477%2C1758223%2C1760160%2C1761481%2C1761771");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1692655");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1746448");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1751678");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1755081");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1757138");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1760674");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1761981");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-29914: Fullscreen notification bypass using popups
When reusing existing popups Firefox would have allowed them to cover the fullscreen notification UI, which could have enabled browser spoofing attacks.

CVE-2022-29909: Bypassing permission prompt in nested browsing contexts
Documents in deeply-nested cross-origin browsing contexts could have obtained permissions granted to the top-level origin, bypassing the existing prompt and wrongfully inheriting the top-level permissions.

CVE-2022-29916: Leaking browser history with CSS variables
Firefox behaved slightly differently for already known resources when loading CSS resources involving CSS variables. This could have been used to probe the browser history.

CVE-2022-29911: iframe Sandbox bypass
Firefox did not properly protect against top-level navigations for an iframe sandbox with a policy relaxed through a keyword like allow-top-navigation-by-user-activation.

CVE-2022-29912: Reader mode bypassed SameSite cookies
Requests initiated through reader mode did not properly omit cookies with a SameSite attribute.

CVE-2022-29910: Firefox for Android forgot HTTP Strict Transport Security settings
When closed or sent to the background, Firefox for Android would not properly record and persist HSTS settings.Note: This issue only affected Firefox for Android. Other operating systems are unaffected.

CVE-2022-29915: Leaking cross-origin redirect through the Performance API
The Performance API did not properly hide the fact whether a request cross-origin resource has observed redirects.

CVE-2022-29917: Memory safety bugs fixed in Firefox 100 and Firefox ESR 91.9
Mozilla developers Andrew McCreight, Gabriele Svelto, Tom Ritter and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 99 and Firefox ESR 91.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2022-29918: Memory safety bugs fixed in Firefox 100
Mozilla developers Gabriele Svelto, Randell Jesup and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 99. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 100.");

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

if (version_is_less(version: version, test_version: "100")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "100", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
