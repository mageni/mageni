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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.20");
  script_cve_id("CVE-2017-16541", "CVE-2018-12375", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12379", "CVE-2018-12381", "CVE-2018-12382", "CVE-2018-12383", "CVE-2018-18499");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-06 14:50:00 +0000 (Thu, 06 Dec 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-20) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-20");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-20/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1469309%2C1469914%2C1450989%2C1480092%2C1480517%2C1481093%2C1478575%2C1471953%2C1473161%2C1466991%2C1468738%2C1483120%2C1467363%2C1472925%2C1466577%2C1467889%2C1480521%2C1478849");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1478849%2C1433502%2C1480965%2C894215%2C1462693%2C1475431%2C1461027");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1412081");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1435319");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1459383");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1468523");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1470260");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1473113");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1475775");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1479311");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-12377: Use-after-free in refresh driver timers
A use-after-free vulnerability can occur when refresh driver timers are refreshed in some circumstances during shutdown when the timer is deleted while still in use. This results in a potentially exploitable crash.

CVE-2018-12378: Use-after-free in IndexedDB
A use-after-free vulnerability can occur when an IndexedDB index is deleted while still in use by JavaScript code that is providing payload values to be stored. This results in a potentially exploitable crash.

CVE-2018-18499: Same-origin policy violation using meta refresh and performance.getEntries to steal cross-origin URLs
A same-origin policy violation allowing the theft of cross-origin URL entries when using a <meta> meta http-equiv='refresh' on a page to cause a redirection to another site using performance.getEntries(). This is a same-origin policy violation and could allow for data theft.

CVE-2018-12379: Out-of-bounds write with malicious MAR file
When the Mozilla Updater opens a MAR format file which contains a very long item filename, an out-of-bounds write can be triggered, leading to a potentially exploitable crash. This requires running the Mozilla Updater manually on the local system with the malicious MAR file in order to occur.

CVE-2017-16541: Proxy bypass using automount and autofs
Browser proxy settings can be bypassed by using the automount feature with autofs to create a mount point on the local file system. Content can be loaded from this mounted file system directly using a file: URI, bypassing configured proxy settings. Note: this issue only affects OS X in default configurations. On Linux systems, autofs must be installed for the vulnerability to occur and Windows is not affected.

CVE-2018-12381: Dragging and dropping Outlook email message results in page navigation
Manually dragging and dropping an Outlook email message into the browser will trigger a page navigation when the message's mail columns are incorrectly interpreted as a URL. Note: this issue only affects Windows operating systems with Outlook installed. Other operating systems are not affected.

CVE-2018-12382: Addressbar spoofing with javascript URI on Firefox for Android
The displayed addressbar URL can be spoofed on Firefox for Android using a javascript: URI in concert with JavaScript to insert text before the loaded domain name, scrolling the loaded domain out of view to the right. This can lead to user confusion. This vulnerability only affects Firefox for Android.

CVE-2018-12383: Setting a master password post-Firefox 58 does not delete unencrypted previously stored passwords
If a user saved passwords before Firefox 58 and then later set a master password, an unencrypted copy of these passwords is still accessible. This is because the older stored password file was not deleted when the data was copied to a new format starting in Firefox 58. The new master password ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 62.");

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

if (version_is_less(version: version, test_version: "62")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "62", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
