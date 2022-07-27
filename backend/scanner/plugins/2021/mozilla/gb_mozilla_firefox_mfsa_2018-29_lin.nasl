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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2018.29");
  script_cve_id("CVE-2018-12405", "CVE-2018-12406", "CVE-2018-12407", "CVE-2018-17466", "CVE-2018-18492", "CVE-2018-18493", "CVE-2018-18494", "CVE-2018-18495", "CVE-2018-18496", "CVE-2018-18497", "CVE-2018-18498", "CVE-2018-18510");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 11:55:00 +0000 (Tue, 12 Mar 2019)");

  script_name("Mozilla Firefox Security Advisory (MFSA2018-29) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2018-29");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2018-29/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1456947%2C1475669%2C1504816%2C1502886%2C1500064%2C1500310%2C1500696%2C1499198%2C1434490%2C1481745%2C1458129");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1494752%2C1498765%2C1503326%2C1505181%2C1500759%2C1504365%2C1506640%2C1503082%2C1502013%2C1510471");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1422231");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1427585");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1487964");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1488180");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1488295");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1499861");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1500011");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1504452");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1505973");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1507702");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2018-12407: Buffer overflow with ANGLE library when using VertexBuffer11 module
A buffer overflow occurs when drawing and validating elements with the ANGLE graphics library, used for WebGL content, when working with the VertexBuffer11 module. This results in a potentially exploitable crash.

CVE-2018-17466: Buffer overflow and out-of-bounds read in ANGLE library with TextureStorage11
A buffer overflow and out-of-bounds read can occur in TextureStorage11 within the ANGLE graphics library, used for WebGL content. This results in a potentially exploitable crash.

CVE-2018-18492: Use-after-free with select element
A use-after-free vulnerability can occur after deleting a selection element due to a weak reference to the select element in the options collection. This results in a potentially exploitable crash.

CVE-2018-18493: Buffer overflow in accelerated 2D canvas with Skia
A buffer overflow can occur in the Skia library during buffer offset calculations with hardware accelerated canvas 2D actions due to the use of 32-bit calculations instead of 64-bit. This results in a potentially exploitable crash.

CVE-2018-18494: Same-origin policy violation using location attribute and performance.getEntries to steal cross-origin URLs
A same-origin policy violation allowing the theft of cross-origin URL entries when using the Javascript location property to cause a redirection to another site using performance.getEntries(). This is a same-origin policy violation and could allow for data theft.

CVE-2018-18495: WebExtension content scripts can be loaded in about: pages
WebExtension content scripts can be loaded into about: pages in some circumstances, in violation of the permissions granted to extensions. This could allow an extension to interfere with the loading and usage of these pages and use capabilities that were intended to be restricted from extensions.

CVE-2018-18496: Embedded feed preview page can be abused for clickjacking
When the RSS Feed preview about:feeds page is framed within another page, it can be used in concert with scripted content for a clickjacking attack that confuses users into downloading and executing an executable file from a temporary directory. Note: This issue only affects Windows operating systems. Other operating systems are not affected.

CVE-2018-18497: WebExtensions can load arbitrary URLs through pipe separators
Limitations on the URIs allowed to WebExtensions by the browser.windows.create API can be bypassed when a pipe in the URL field is used within the extension to load multiple pages as a single argument. This could allow a malicious WebExtension to opened privileged about: or file: locations.

CVE-2018-18498: Integer overflow when calculating buffer sizes for images
A potential vulnerability leading to an integer overflow can occur during buffer size calculations for images when a raw value is used instead of the checked value. This can ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 64.");

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

if (version_is_less(version: version, test_version: "64")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "64", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
