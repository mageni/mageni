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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.12");
  script_cve_id("CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6823", "CVE-2020-6824", "CVE-2020-6825", "CVE-2020-6826");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-01 11:38:00 +0000 (Fri, 01 May 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-12) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-12");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-12/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1572541%2C1620193%2C1620203");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1613009%2C1613195%2C1616734%2C1617488%2C1619229%2C1620719%2C1624897");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1544181");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1614919");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1621853");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1625404");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-6821: Uninitialized memory could be read when using the WebGL copyTexSubImage method
When reading from areas partially or fully outside the source resource with WebGL's copyTexSubImage method, the specification requires the returned values be zero. Previously, this memory was uninitialized, leading to potentially sensitive data disclosure.

CVE-2020-6822: Out of bounds write in GMPDecodeData when processing large images
On 32-bit builds, an out of bounds write could have occurred when processing an image larger than 4 GB in GMPDecodeData. It is possible that with enough effort this could have been exploited to run arbitrary code.

CVE-2020-6823: Malicious Extension could obtain auth codes from OAuth login flows
A malicious extension could have called browser.identity.launchWebAuthFlow, controlling the redirect_uri, and through the Promise returned, obtain the Auth code and gain access to the user's account at the service provider.

CVE-2020-6824: Generated passwords may be identical on the same site between separate private browsing sessions
Initially, a user opens a Private Browsing Window and generates a password for a site, then closes the Private Browsing Window but leaves Firefox open. Subsequently, if the user had opened a new Private Browsing Window, revisited the same site, and generated a new password - the generated passwords would have been identical, rather than independent.

CVE-2020-6825: Memory safety bugs fixed in Firefox 75 and Firefox ESR 68.7
Mozilla developers and community members Tyson Smith and Christian Holler reported memory safety bugs present in Firefox 74 and Firefox ESR 68.6. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2020-6826: Memory safety bugs fixed in Firefox 75
Mozilla developers Tyson Smith, Bob Clary, and Alexandru Michis reported memory safety bugs present in Firefox 74. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 75.");

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

if (version_is_less(version: version, test_version: "75")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "75", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
