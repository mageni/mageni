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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2021.43");
  script_cve_id("CVE-2021-32810", "CVE-2021-38496", "CVE-2021-38497", "CVE-2021-38498", "CVE-2021-38499", "CVE-2021-38500", "CVE-2021-38501");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-11 15:52:00 +0000 (Wed, 11 Aug 2021)");

  script_name("Mozilla Firefox Security Advisory (MFSA2021-43) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2021-43");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-43/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1685354%2C1715755%2C1723176");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1723170%2C1725356%2C1727364");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1725854%2C1728321");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1667102");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1725335");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1726621");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1729642");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1729813");
  script_xref(name:"URL", value:"https://github.com/crossbeam-rs/crossbeam/security/advisories/GHSA-pqqp-xmhj-wgcw");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2021-38496: Use-after-free in MessageTask
During operations on MessageTasks, a task may have been removed while it was still scheduled, resulting in memory corruption and a potentially exploitable crash.

CVE-2021-38497: Validation message could have been overlaid on another origin
Through use of reportValidity() and window.open(), a plain-text validation message could have been overlaid on another origin, leading to possible user confusion and spoofing attacks.

CVE-2021-38498: Use-after-free of nsLanguageAtomService object
During process shutdown, a document could have caused a use-after-free of a languages service object, leading to memory corruption and a potentially exploitable crash.

CVE-2021-32810: Data race in crossbeam-deque
In the crossbeam crate, one or more tasks in the worker queue could have been be popped twice instead of other tasks that are forgotten and never popped. If tasks are allocated on the heap, this could have caused a double free and a memory leak.

CVE-2021-38500: Memory safety bugs fixed in Firefox 93, Firefox ESR 78.15, and Firefox ESR 91.2
Mozilla developers and community members Andreas Pehrson and Christian Holler reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

MOZ-2021-0008: Use-after-free in HTTP2 Session object
A use-after-free could have occurred when an HTTP2 session object was released on a different thread, leading to memory corruption and a potentially exploitable crash.Note: This issue is pending a CVE assignment and will be updated when available.

CVE-2021-38501: Memory safety bugs fixed in Firefox 93 and Firefox ESR 91.2
Mozilla developers and community members Kevin Brosnan, Mihai Alexandru Michis, and Christian Holler reported memory safety bugs present in Firefox 92 and Firefox ESR 91.1. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2021-38499: Memory safety bugs fixed in Firefox 93
Mozilla developers and community members Julien Cristau, Christian Holler reported memory safety bugs present in Firefox 92. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 93.");

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

if (version_is_less(version: version, test_version: "93")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "93", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
