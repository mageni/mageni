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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2016.85");
  script_cve_id("CVE-2016-2827", "CVE-2016-5256", "CVE-2016-5257", "CVE-2016-5270", "CVE-2016-5271", "CVE-2016-5272", "CVE-2016-5273", "CVE-2016-5274", "CVE-2016-5275", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5279", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5282", "CVE-2016-5283", "CVE-2016-5284");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-29 23:29:00 +0000 (Sat, 29 Jul 2017)");

  script_name("Mozilla Firefox Security Advisory (MFSA2016-85) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2016-85");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2016-85/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1288588%2C1287204%2C1294407%2C1293347%2C1288780%2C1288555%2C1289280%2C1294095%2C1277213");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1290244%2C1282746%2C1268034%2C1296078%2C1297099%2C1276413%2C1296087");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1249522");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1280387");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1282076");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1284690");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1287316");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1287721");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1288946");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1289085");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1289970");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1291016");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1291665");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1294677");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=129793");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1303127");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=928187");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=932335");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2016-2827: Out-of-bounds read in mozilla::net::IsValidReferrerPolicy
A content security policy (CSP) containing a referrer directive with no values can cause a non-exploitable crash.

CVE-2016-5270: Heap-buffer-overflow in nsCaseTransformTextRunFactory::TransformString
An out-of-bounds write of a boolean value during text conversion with some unicode characters

CVE-2016-5271: Out-of-bounds read in PropertyProvider::GetSpacingInternal
An out-of-bounds read during the processing of text runs in some pages using display:contents.

CVE-2016-5272: Bad cast in nsImageGeometryMixin
A bad cast when processing layout with input elements can result in a potentially exploitable crash.

CVE-2016-5273: crash in mozilla::a11y::HyperTextAccessible::GetChildOffset
A potentially exploitable crash in accessibility.

CVE-2016-5276: Heap-use-after-free in mozilla::a11y::DocAccessible::ProcessInvalidationList
A use-after-free vulnerability triggered by setting a aria-owns attribute.

CVE-2016-5274: use-after-free in nsFrameManager::CaptureFrameState
A use-after-free issue in web animations during restyling.

CVE-2016-5277: Heap-use-after-free in nsRefreshDriver::Tick
A use-after-free vulnerability with web animations when destroying a timeline.

CVE-2016-5275: Buffer overflow in mozilla::gfx::FilterSupport::ComputeSourceNeededRegions
A buffer overflow when working with empty filters during canvas rendering.

CVE-2016-5278: Heap-buffer-overflow in nsBMPEncoder::AddImageFrame
A potentially exploitable crash caused by a buffer overflow while encoding image frames to images.

CVE-2016-5279: Full local path of files is available to web pages after drag and drop
The full path to local files is available to scripts when local files are drag and dropped into Firefox.

CVE-2016-5280: Use-after-free in mozilla::nsTextNodeDirectionalityMap::RemoveElementFromMap
Use-after-free vulnerability when changing text direction.

CVE-2016-5281: use-after-free in DOMSVGLength
Use-after-free vulnerability when manipulating SVG format content through script.

CVE-2016-5282: Don't allow content to request favicons from non-whitelisted schemes
Favicons can be loaded through non-whitelisted protocols, such as jar:.

CVE-2016-5283: Iframe src fragment timing attack can reveal cross-origin data
A timing attack vulnerability using iframes to potentially reveal private data using document resizes and link colors.

CVE-2016-5284: Add-on update site certificate pin expiration
Due to flaws in the process we used to update 'Preloaded Public Key Pinning' in our releases, the pinning for add-on updates became ineffective in early September. An attacker who was able to get a mis-issued certificate for a Mozilla web site could send malicious add-on updates to users on networks controlled by the attacker. Users who have not installed any add-ons are not affected.

CVE-2016-5256: Memory safety bugs fixed in Firefox 49
Mozilla ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 49.");

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

if (version_is_less(version: version, test_version: "49")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "49", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
