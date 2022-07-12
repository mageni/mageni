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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.20");
  script_cve_id("CVE-2020-12399", "CVE-2020-12405", "CVE-2020-12406", "CVE-2020-12407", "CVE-2020-12408", "CVE-2020-12409", "CVE-2020-12410", "CVE-2020-12411");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-22 14:15:00 +0000 (Wed, 22 Jul 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-20) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-20");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-20/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1619305%2C1632717");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1620972%2C1625333");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1623888");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1629506");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1631576");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1631618");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1637112");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1639590");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-12399: Timing attack on DSA signatures in NSS library
NSS has shown timing differences when performing DSA signatures, which was exploitable and could eventually leak private keys.

CVE-2020-12405: Use-after-free in SharedWorkerService
When browsing a malicious page, a race condition in our SharedWorkerService could occur and lead to a potentially exploitable crash.

CVE-2020-12406: JavaScript type confusion with NativeTypes
Mozilla Developer Iain Ireland discovered a missing type check during unboxed objects removal, resulting in a crash. We presume that with enough effort that it could be exploited to run arbitrary code.

CVE-2020-12407: WebRender leaking GPU memory when using border-image CSS directive
Mozilla Developer Nicolas Silva found that when using WebRender, Firefox would under certain conditions leak arbitrary GPU memory to the visible screen. The leaked memory content was visible to the user, but not observable from web content.

CVE-2020-12408: URL spoofing when using IP addresses
When browsing a document hosted on an IP address, an attacker could insert certain characters to flip domain and path information in the address bar.

CVE-2020-12409: URL spoofing with unicode characters
When using certain blank characters in a URL, they where incorrectly rendered as spaces instead of an encoded URL.

CVE-2020-12410: Memory safety bugs fixed in Firefox 77 and Firefox ESR 68.9
Mozilla developers Tom Tung and Karl Tomlinson reported memory safety bugs present in Firefox 76 and Firefox ESR 68.8. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2020-12411: Memory safety bugs fixed in Firefox 77
Mozilla developers :Gijs (he/him), Randell Jesup reported memory safety bugs present in Firefox 76. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 77.");

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

if (version_is_less(version: version, test_version: "77")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "77", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
