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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.07");
  script_cve_id("CVE-2019-9788", "CVE-2019-9789", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9797", "CVE-2019-9798", "CVE-2019-9799", "CVE-2019-9801", "CVE-2019-9802", "CVE-2019-9803", "CVE-2019-9804", "CVE-2019-9805", "CVE-2019-9806", "CVE-2019-9807", "CVE-2019-9808", "CVE-2019-9809");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-13 08:29:00 +0000 (Mon, 13 May 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-07) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-07");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-07/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1518001%2C1521304%2C1521214%2C1506665%2C1516834%2C1518774%2C1524755%2C1523362%2C1524214%2C1529203");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1520483%2C1522987%2C1528199%2C1519337%2C1525549%2C1516179%2C1518524%2C1518331%2C1526579%2C1512567%2C1524335%2C1448505%2C1518821");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1282430");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1362050");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1415508");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1434634");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1437009");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1505678");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1514682");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1515863");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1518026");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1521360");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1523249");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525145");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1525267");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1527534");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1527717");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1528829");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1528909");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1530103");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1530958");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1531277");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1532599");
  script_xref(name:"URL", value:"https://w3c.github.io/webappsec-upgrade-insecure-requests/");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-9790: Use-after-free when removing in-use DOM elements
A use-after-free vulnerability can occur when a raw pointer to a DOM element on a page is obtained using JavaScript and the element is then removed while still in use. This results in a potentially exploitable crash.

CVE-2019-9791: Type inference is incorrect for constructors entered through on-stack replacement with IonMonkey
The type inference system allows the compilation of functions that can cause type confusions between arbitrary objects when compiled through the IonMonkey just-in-time (JIT) compiler and when the constructor function is entered through on-stack replacement (OSR). This allows for possible arbitrary reading and writing of objects during an exploitable crash.

CVE-2019-9792: IonMonkey leaks JS_OPTIMIZED_OUT magic value to script
The IonMonkey just-in-time (JIT) compiler can leak an internal JS_OPTIMIZED_OUT magic value to the running script during a bailout. This magic value can then be used by JavaScript to achieve memory corruption, which results in a potentially exploitable crash.

CVE-2019-9793: Improper bounds checks when Spectre mitigations are disabled
A mechanism was discovered that removes some bounds checking for string, array, or typed array accesses if Spectre mitigations have been disabled. This vulnerability could allow an attacker to create an arbitrary value in compiled JavaScript, for which the range analysis will infer a fully controlled, incorrect range in circumstances where users have explicitly disabled Spectre mitigations. Note: Spectre mitigations are currently enabled for all users by default settings.

CVE-2019-9794: Command line arguments not discarded during execution
A vulnerability was discovered where specific command line arguments are not properly discarded during Firefox invocation as a shell handler for URLs. This could be used to retrieve and execute files whose location is supplied through these command line arguments if Firefox is configured as the default URI handler for a given URI scheme in third party applications and these applications insufficiently sanitize URL data. Note: This issue only affects Windows operating systems. Other operating systems are unaffected.

CVE-2019-9795: Type-confusion in IonMonkey JIT compiler
A vulnerability where type-confusion in the IonMonkey just-in-time (JIT) compiler could potentially be used by malicious JavaScript to trigger a potentially exploitable crash.

CVE-2019-9796: Use-after-free with SMIL animation controller
A use-after-free vulnerability can occur when the SMIL animation controller incorrectly registers with the refresh driver twice when only a single registration is expected. When a registration is later freed with the removal of the animation controller element, the refresh driver incorrectly leaves a dangling pointer to the driver's observer array.

CVE-2019-9797: Cross-origin theft of images ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 66.");

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

if (version_is_less(version: version, test_version: "66")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "66", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
