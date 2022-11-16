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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.47");
  script_cve_id("CVE-2022-40674", "CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406", "CVE-2022-45407", "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410", "CVE-2022-45411", "CVE-2022-45412", "CVE-2022-45415", "CVE-2022-45416", "CVE-2022-45417", "CVE-2022-45418", "CVE-2022-45419", "CVE-2022-45420", "CVE-2022-45421");
  script_tag(name:"creation_date", value:"2022-11-16 09:28:04 +0000 (Wed, 16 Nov 2022)");
  script_version("2022-11-16T09:32:32+0000");
  script_tag(name:"last_modification", value:"2022-11-16 09:32:32 +0000 (Wed, 16 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-16 03:09:00 +0000 (Fri, 16 Sep 2022)");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-47) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-47");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-47/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1767920%2C1789808%2C1794061");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1658869");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1716082");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1762078");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1790311");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1790815");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1791029");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1791314");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1791598");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1791975");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1792643");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1793314");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1793551");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1793676");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1793829");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1794508");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1795815");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1796901");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-45403: Service Workers might have learned size of cross-origin media files
Service Workers should not be able to infer information about opaque cross-origin responses, but timing information for cross-origin media combined with Range requests might have allowed them to determine the presence or length of a media file.

CVE-2022-45404: Fullscreen notification bypass
Through a series of popup and window.print() calls, an attacker can cause a window to go fullscreen without the user seeing the notification prompt, resulting in potential user confusion or spoofing attacks.

CVE-2022-45405: Use-after-free in InputStream implementation
Freeing arbitrary nsIInputStream's on a different thread than creation could have led to a use-after-free and potentially exploitable crash.

CVE-2022-45406: Use-after-free of a JavaScript Realm
If an out-of-memory condition occurred when creating a JavaScript global, a JavaScript realm may be deleted while references to it lived on in a BaseShape. This could lead to a use-after-free causing a potentially exploitable crash.

CVE-2022-45407: Loading fonts on workers was not thread-safe
If an attacker loaded a font using FontFace() on a background worker, a use-after-free could have occurred, leading to a potentially exploitable crash.

CVE-2022-45408: Fullscreen notification bypass via windowName
Through a series of popups that reuse windowName, an attacker can cause a window to go fullscreen without the user seeing the notification prompt, resulting in potential user confusion or spoofing attacks.

CVE-2022-45409: Use-after-free in Garbage Collection
The garbage collector could have been aborted in several states and zones and GCRuntime::finishCollection may not have been called, leading to a use-after-free and potentially exploitable crash

CVE-2022-45410: ServiceWorker-intercepted requests bypassed SameSite cookie policy
When a ServiceWorker intercepted a request with FetchEvent, the origin of the request was lost after the ServiceWorker took ownership of it. This had the effect of negating SameSite cookie protections. This was addressed in the spec and then in browsers.

CVE-2022-45411: Cross-Site Tracing was possible via non-standard override headers
Cross-Site Tracing occurs when a server will echo a request back via the Trace method, allowing an XSS attack to access to authorization headers and cookies inaccessible to JavaScript (such as cookies protected by HTTPOnly). To mitigate this attack, browsers placed limits on fetch() and XMLHttpRequest, however some webservers have implemented non-standard headers such as X-Http-Method-Override that override the HTTP method, and made this attack possible again. Firefox has applied the same mitigations to the use of this and similar headers.

CVE-2022-45412: Symlinks may resolve to partially uninitialized buffers
When resolving a symlink such as file:///proc/self/fd/1, an error message ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 107.");

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

if (version_is_less(version: version, test_version: "107")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "107", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
