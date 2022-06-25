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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.24");
  script_cve_id("CVE-2020-12402", "CVE-2020-12415", "CVE-2020-12416", "CVE-2020-12417", "CVE-2020-12418", "CVE-2020-12419", "CVE-2020-12420", "CVE-2020-12421", "CVE-2020-12422", "CVE-2020-12423", "CVE-2020-12424", "CVE-2020-12425", "CVE-2020-12426");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 00:15:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-24) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-24");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-24/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1608068%2C1609951%2C1631187%2C1637682");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1308251");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1450353");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1562600");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1586630");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1631597");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1634738");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1639734");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1640737");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1641303");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1642400");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1643437");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1643874");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-12415: AppCache manifest poisoning due to url encoded character processing
When %2F was present in a manifest URL, Firefox's AppCache behavior may have become confused and allowed a manifest to be served from a subdirectory. This could cause the appcache to be used to service requests for the top level directory.

CVE-2020-12416: Use-after-free in WebRTC VideoBroadcaster
A VideoStreamEncoder may have been freed in a race condition with VideoBroadcaster::AddOrUpdateSink, resulting in a use-after-free, memory corruption, and a potentially exploitable crash.

CVE-2020-12417: Memory corruption due to missing sign-extension for ValueTags on ARM64
Due to confusion about ValueTags on JavaScript Objects, an object may pass through the type barrier, resulting in memory corruption and a potentially exploitable crash.Note: this issue only affects Firefox on ARM64 platforms.

CVE-2020-12418: Information disclosure due to manipulated URL object
Manipulating individual parts of a URL object could have caused an out-of-bounds read, leaking process memory to malicious JavaScript.

CVE-2020-12419: Use-after-free in nsGlobalWindowInner
When processing callbacks that occurred during window flushing in the parent process, the associated window may die, causing a use-after-free condition. This could have led to memory corruption and a potentially exploitable crash.

CVE-2020-12420: Use-After-Free when trying to connect to a STUN server
When trying to connect to a STUN server, a race condition could have caused a use-after-free of a pointer, leading to memory corruption and a potentially exploitable crash.

CVE-2020-12402: RSA Key Generation vulnerable to side-channel attack
During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes. We would like to thank Sohaib ul Hassan for contributing a fix for this issue as well.Note: An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected, but products built on top of it might.

CVE-2020-12421: Add-On updates did not respect the same certificate trust rules as software updates
When performing add-on updates, certificate chains terminating in non-built-in-roots were rejected (even if they were legitimately added by an administrator.) This could have caused add-ons to become out-of-date silently without notification to the user.

CVE-2020-12422: Integer overflow in nsJPEGEncoder::emptyOutputBuffer
In non-standard configurations, a JPEG image created by JavaScript could have caused an internal variable to overflow, resulting in an out of bounds write, memory corruption, and a potentially exploitable crash.

CVE-2020-12423: DLL Hijacking due to searching %PATH% ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 78.");

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

if (version_is_less(version: version, test_version: "78")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "78", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
