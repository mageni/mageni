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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2017.01");
  script_cve_id("CVE-2017-5373", "CVE-2017-5374", "CVE-2017-5375", "CVE-2017-5376", "CVE-2017-5377", "CVE-2017-5378", "CVE-2017-5379", "CVE-2017-5380", "CVE-2017-5381", "CVE-2017-5382", "CVE-2017-5383", "CVE-2017-5384", "CVE-2017-5385", "CVE-2017-5386", "CVE-2017-5387", "CVE-2017-5388", "CVE-2017-5389", "CVE-2017-5390", "CVE-2017-5391", "CVE-2017-5392", "CVE-2017-5393", "CVE-2017-5394", "CVE-2017-5395", "CVE-2017-5396");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-02 17:34:00 +0000 (Thu, 02 Aug 2018)");

  script_name("Mozilla Firefox Security Advisory (MFSA2017-01) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2017-01");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2017-01/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1322315%2C1328834%2C1322420%2C1285833%2C1285960%2C1328251%2C1331058%2C1325938%2C1325877");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1325344%2C1317501%2C1311319%2C1329989%2C1300145%2C1322305%2C1288561%2C1295747%2C1318766%2C1297808%2C1321374%2C1324810%2C1313385%2C1319888%2C1302231%2C1307458%2C1293327%2C1315447%2C1319456");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1017616");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1222798");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1255474");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1281482");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1293463");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1293709");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295023");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295322");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1295945");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1297361");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1306883");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1308688");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1309198");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1309282");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1309310");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1311687");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1312001");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1319070");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1322107");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1323338");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1324716");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1325200");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1329403");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1330769");
  script_xref(name:"URL", value:"https://www.contextis.com//resources/blog/leaking-https-urls-20-year-old-vulnerability/");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2017-5375: Excessive JIT code allocation allows bypass of ASLR and DEP
JIT code allocation can allow for a bypass of ASLR and DEP protections leading to potential memory corruption attacks.

CVE-2017-5376: Use-after-free in XSL
Use-after-free while manipulating XSL in XSLT documents

CVE-2017-5377: Memory corruption with transforms to create gradients in Skia
A memory corruption vulnerability in Skia that can occur when using transforms to make gradients, resulting in a potentially exploitable crash.

CVE-2017-5378: Pointer and frame data leakage of Javascript objects
Hashed codes of JavaScript objects are shared between pages. This allows for pointer leaks because an object's address can be discovered through hash codes, and also allows for data leakage of an object's content using these hash codes.

CVE-2017-5379: Use-after-free in Web Animations
Use-after-free vulnerability in Web Animations when interacting with cycle collection found through fuzzing.

CVE-2017-5380: Potential use-after-free during DOM manipulations
A potential use-after-free found through fuzzing during DOM manipulation of SVG content.

CVE-2017-5390: Insecure communication methods in Developer Tools JSON viewer
The JSON viewer in the Developer Tools uses insecure methods to create a communication channel for copying and viewing JSON or HTTP headers data, allowing for potential privilege escalation.

CVE-2017-5389: WebExtensions can install additional add-ons via modified host requests
WebExtensions could use the mozAddonManager API by modifying the CSP headers on sites with the appropriate permissions and then using host requests to redirect script loads to a malicious site. This allows a malicious extension to then install additional extensions without explicit user permission.

CVE-2017-5396: Use-after-free with Media Decoder
A use-after-free vulnerability in the Media Decoder when working with media files when some events are fired after the media elements are freed from memory.

CVE-2017-5381: Certificate Viewer exporting can be used to navigate and save to arbitrary filesystem locations
The 'export' function in the Certificate Viewer can force local filesystem navigation when the 'common name' in a certificate contains slashes, allowing certificate content to be saved in unsafe locations with an arbitrary filename.

CVE-2017-5382: Feed preview can expose privileged content errors and exceptions
Feed preview for RSS feeds can be used to capture errors and exceptions generated by privileged content, allowing for the exposure of internal information not meant to be seen by web content.

CVE-2017-5383: Location bar spoofing with unicode characters
URLs containing certain unicode glyphs for alternative hyphens and quotes do not properly trigger punycode display, allowing for domain name spoofing attacks in the location bar.

CVE-2017-5384: Information disclosure via Proxy Auto-Config ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 51.");

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

if (version_is_less(version: version, test_version: "51")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "51", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
