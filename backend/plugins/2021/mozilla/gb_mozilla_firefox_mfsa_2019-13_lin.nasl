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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.13");
  script_cve_id("CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11694", "CVE-2019-11695", "CVE-2019-11696", "CVE-2019-11697", "CVE-2019-11698", "CVE-2019-11699", "CVE-2019-11700", "CVE-2019-11701", "CVE-2019-7317", "CVE-2019-9800", "CVE-2019-9814", "CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818", "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-9821");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-26 14:23:00 +0000 (Fri, 26 Jul 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-13) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-13");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-13/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1527592%2C1534536%2C1520132%2C1543159%2C1539393%2C1459932%2C1459182%2C1516425");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1540166%2C1534593%2C1546327%2C1540136%2C1538736%2C1538042%2C1535612%2C1499719%2C1499108%2C1538619%2C1535194%2C1516325%2C1542324%2C1542097%2C1532465%2C1533554%2C1541580");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1392955");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1440079");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1445844");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1518627");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1528939");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1532525");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1532553");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1534196");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1536405");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1536768");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1539125");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1540221");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1542465");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1542581");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1542829");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1543191");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1544670");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1546544");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1549833");
  script_xref(name:"URL", value:"https://mdsattacks.com/");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-9815: Disable hyperthreading on content JavaScript threads on macOS
If hyperthreading is not disabled, a timing attack vulnerability exists, similar to previous Spectre attacks. Apple has shipped macOS 10.14.5 with an option to disable hyperthreading in applications running untrusted code in a thread through a new sysctl. Firefox now makes use of it on the main thread and any worker threads. Note: users need to update to macOS 10.14.5 in order to take advantage of this change.

CVE-2019-9816: Type confusion with object groups and UnboxedObjects
A possible vulnerability exists where type confusion can occur when manipulating JavaScript objects in object groups, allowing for the bypassing of security checks within these groups. Note: this vulnerability has only been demonstrated with UnboxedObjects, which are disabled by default on all supported releases.

CVE-2019-9817: Stealing of cross-domain images using canvas
Images from a different domain can be read using a canvas object in some circumstances. This could be used to steal image data from a different site in violation of same-origin policy.

CVE-2019-9818: Use-after-free in crash generation server
A race condition is present in the crash generation server used to generate data for the crash reporter. This issue can lead to a use-after-free in the main process, resulting in a potentially exploitable crash and a sandbox escape. Note: this vulnerability only affects Windows. Other operating systems are unaffected.

CVE-2019-9819: Compartment mismatch with fetch API
A vulnerability where a JavaScript compartment mismatch can occur while working with the fetch API, resulting in a potentially exploitable crash.

CVE-2019-9820: Use-after-free of ChromeEventHandler by DocShell
A use-after-free vulnerability can occur in the chrome event handler when it is freed while still in use. This results in a potentially exploitable crash.

CVE-2019-9821: Use-after-free in AssertWorkerThread
A use-after-free vulnerability can occur in AssertWorkerThread due to a race condition with shared workers. This results in a potentially exploitable crash.

CVE-2019-11691: Use-after-free in XMLHttpRequest
A use-after-free vulnerability can occur when working with XMLHttpRequest (XHR) in an event loop, causing the XHR main thread to be called after it has been freed. This results in a potentially exploitable crash.

CVE-2019-11692: Use-after-free removing listeners in the event listener manager
A use-after-free vulnerability can occur when listeners are removed from the event listener manager while still in use, resulting in a potentially exploitable crash.

CVE-2019-11693: Buffer overflow in WebGL bufferdata on Linux
The bufferdata function in WebGL is vulnerable to a buffer overflow with specific graphics drivers on Linux. This could result in malicious content freezing a tab or triggering a potentially exploitable crash. Note: this ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 67.");

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

if (version_is_less(version: version, test_version: "67")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "67", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
