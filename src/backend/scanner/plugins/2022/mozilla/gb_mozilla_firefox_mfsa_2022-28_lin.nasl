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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2022.28");
  script_cve_id("CVE-2022-2505", "CVE-2022-36314", "CVE-2022-36315", "CVE-2022-36316", "CVE-2022-36317", "CVE-2022-36318", "CVE-2022-36319", "CVE-2022-36320");
  script_tag(name:"creation_date", value:"2022-07-27 06:21:44 +0000 (Wed, 27 Jul 2022)");
  script_version("2022-07-27T06:21:44+0000");
  script_tag(name:"last_modification", value:"2022-07-27 06:21:44 +0000 (Wed, 27 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2022-28) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2022-28");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-28/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1759794%2C1760998");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1769739%2C1772824");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1737722");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1759951");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1762520");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1768583");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1771774");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1773894");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2022-36319: Mouse Position spoofing with CSS transforms
When combining CSS properties for overflow and transform, the mouse cursor could interact with different coordinates than displayed.

CVE-2022-36317: Long URL would hang Firefox for Android
When visiting a website with an overly long URL, the user interface would start to hang. Due to session restore, this could lead to a permanent Denial of Service.This bug only affects Firefox for Android. Other operating systems are unaffected.

CVE-2022-36318: Directory indexes for bundled resources reflected URL parameters
When visiting directory listings for chrome:// URLs as source text, some parameters were reflected.

CVE-2022-36314: Opening local <code>.lnk</code> files could cause unexpected network loads
When opening a Windows shortcut from the local filesystem, an attacker could supply a remote path that would lead to unexpected network requests from the operating system.This bug only affects Firefox for Windows. Other operating systems are unaffected.*

CVE-2022-36315: Preload Cache Bypasses Subresource Integrity
When loading a script with Subresource Integrity, attackers with an injection capability could trigger the reuse of previously cached entries with incorrect, different integrity metadata.

CVE-2022-36316: Performance API leaked whether a cross-site resource is redirecting
When using the Performance API, an attacker was able to notice subtle differences between PerformanceEntries and thus learn whether the target URL had been subject to a redirect.

CVE-2022-36320: Memory safety bugs fixed in Firefox 103
Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 102. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2022-2505: Memory safety bugs fixed in Firefox 103 and 102.1
Mozilla developers and the Mozilla Fuzzing Team reported memory safety bugs present in Firefox 102. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 103.");

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

if (version_is_less(version: version, test_version: "103")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "103", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
