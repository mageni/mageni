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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2019.25");
  script_cve_id("CVE-2019-11734", "CVE-2019-11735", "CVE-2019-11736", "CVE-2019-11737", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11741", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11751", "CVE-2019-11752", "CVE-2019-11753", "CVE-2019-11758", "CVE-2019-5849", "CVE-2019-9812");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-15T10:47:05+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-04 18:15:00 +0000 (Fri, 04 Oct 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2019-25) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2019-25");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-25/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1352875%2C1557208%2C1560641");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1561404%2C1561484%2C1568047%2C1561912%2C1565744%2C1568858%2C1570358");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1563133%2C1573160");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1388015");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1452037");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1501152");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1536227");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1538008");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1538015");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1539595");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1551913");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1552206");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1555838");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1559715");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1560495");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1562033");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1564449");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1564481");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1564588");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1565374");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1568397");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1572838");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1574980");
  script_xref(name:"URL", value:"https://w3c.github.io/navigation-timing");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2019-11751: Malicious code execution through command line parameters
Logging-related command line parameters are not properly sanitized when Firefox is launched by another program, such as when a user clicks on malicious links in a chat application. This can be used to write a log file to an arbitrary location such as the Windows 'Startup' folder. Note: this issue only affects Firefox on Windows operating systems.

CVE-2019-11746: Use-after-free while manipulating video
A use-after-free vulnerability can occur while manipulating video elements if the body is freed while still in use. This results in a potentially exploitable crash.

CVE-2019-11744: XSS by breaking out of title and textarea elements using innerHTML
Some HTML elements, such as <title> and <textarea>, can contain literal angle brackets without treating them as markup. It is possible to pass a literal closing tag to .innerHTML on these elements, and subsequent content after that will be parsed as if it were outside the tag. This can lead to XSS if a site does not filter user input as strictly for these elements as it does for other elements.

CVE-2019-11742: Same-origin policy violation with SVG filters and canvas to steal cross-origin images
A same-origin policy violation occurs allowing the theft of cross-origin images through a combination of SVG filters and a <canvas> element due to an error in how same-origin policy is applied to cached image content. The resulting same-origin policy violation could allow for data theft.

CVE-2019-11736: File manipulation and privilege escalation in Mozilla Maintenance Service
The Mozilla Maintenance Service does not guard against files being hardlinked to another file in the updates directory, allowing for the replacement of local files, including the Maintenance Service executable, which is run with privileged access. Additionally, there was a race condition during checks for junctions and symbolic links by the Maintenance Service, allowing for potential local file and directory manipulation to be undetected in some circumstances. This allows for potential privilege escalation by a user with unprivileged local access. Note: These attacks requires local system access and only affects Windows. Other operating systems are not affected.

CVE-2019-11753: Privilege escalation with Mozilla Maintenance Service in custom Firefox installation location
The Firefox installer allows Firefox to be installed to a custom user writable location, leaving it unprotected from manipulation by unprivileged users or malware. If the Mozilla Maintenance Service is manipulated to update this unprotected location and the updated maintenance service in the unprotected location has been altered, the altered maintenance service can run with elevated privileges during the update process due to a lack of integrity checks. This allows for privilege escalation if the executable has been replaced ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 69.");

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

if (version_is_less(version: version, test_version: "69")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "69", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
