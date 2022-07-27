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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.26");
  script_cve_id("CVE-2018-12388", "CVE-2018-12390", "CVE-2018-12391", "CVE-2018-12392", "CVE-2018-12393", "CVE-2018-12395", "CVE-2018-12396", "CVE-2018-12397", "CVE-2018-12398", "CVE-2018-12399", "CVE-2018-12400", "CVE-2018-12401", "CVE-2018-12402", "CVE-2018-12403");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-15T09:13:07+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-26) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-26");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-26/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1472639%2C1485698%2C1301547%2C1471427%2C1379411%2C1482122%2C1486314%2C1487167");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1487098%2C1487660%2C1490234%2C1496159%2C1443748%2C1496340%2C1483905%2C1493347%2C1488803%2C1498701%2C1498482%2C1442010%2C1495245%2C1483699%2C1469486%2C1484905%2C1490561%2C1492524%2C1481844");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1422456");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1447087");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1448305");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1460538");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1467523");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1469916");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1478843");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1483602");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1484753");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1487478");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1488061");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1490276");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1492823");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1495011");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-12391: HTTP Live Stream audio data is accessible cross-origin
During HTTP Live Stream playback on Firefox for Android, audio data can be accessed across origins in violation of security policies. Because the problem is in the underlying Android service, this issue is addressed by treating all HLS streams as cross-origin and opaque to access. Note: this issue only affects Firefox for Android. Desktop versions of Firefox are unaffected.

CVE-2018-12392: Crash with nested event loops
When manipulating user events in nested loops while opening a document through script, it is possible to trigger a potentially exploitable crash due to poor event handling.

CVE-2018-12393: Integer overflow during Unicode conversion while loading JavaScript
A potential vulnerability was found in 32-bit builds where an integer overflow during the conversion of scripts to an internal UTF-16 representation could result in allocating a buffer too small for the conversion. This leads to a possible out-of-bounds write. Note: 64-bit builds are not vulnerable to this issue.

CVE-2018-12395: WebExtension bypass of domain restrictions through header rewriting
By rewriting the Host request headers using the webRequest API, a WebExtension can bypass domain restrictions through domain fronting. This would allow access to domains that share a host that are otherwise restricted.

CVE-2018-12396: WebExtension content scripts can execute in disallowed contexts
A vulnerability where a WebExtension can run content scripts in disallowed contexts following navigation or other events. This allows for potential privilege escalation by the WebExtension on sites where content scripts should not be run.

CVE-2018-12397: Missing warning prompt when WebExtension requests local file access
A WebExtension can request access to local files without the warning prompt stating that the extension will 'Access your data for all websites' being displayed to the user. This allows extensions to run content scripts in local pages without permission warnings when a local file is opened.

CVE-2018-12398: CSP bypass through stylesheet injection in resource URIs
By using the reflected URL in some special resource URIs, such as chrome:, it is possible to inject stylesheets and bypass Content Security Policy (CSP).

CVE-2018-12402: WebBrowserPersist uses incorrect origin information
The internal WebBrowserPersist code does not use correct origin context for a resource being saved. This manifests when sub-resources are loaded as part of 'Save Page As...' functionality. For example, a malicious page could recover a visitor's Windows username and NTLM hash by including resources otherwise unreachable to the malicious page, if they can convince the visitor to save the complete web page. Similarly, SameSite cookies are sent on cross-origin requests when the 'Save Page As...' menu item is selected to save a page, which can result in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 63.");

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

if (version_is_less(version: version, test_version: "63")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "63", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
