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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.36");
  script_cve_id("CVE-2020-12400", "CVE-2020-12401", "CVE-2020-15663", "CVE-2020-15664", "CVE-2020-15665", "CVE-2020-15666", "CVE-2020-15667", "CVE-2020-15668", "CVE-2020-15670", "CVE-2020-6829");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-13 11:51:00 +0000 (Tue, 13 Oct 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-36) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-36");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-36/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1651001%2C1653626%2C1656957");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1450853");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1623116");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1631573");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1631583");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1643199");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1651520");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1651636");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1653371");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1658214");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-15663: Downgrade attack on the Mozilla Maintenance Service could have resulted in escalation of privilege
If Firefox is installed to a user-writable directory, the Mozilla Maintenance Service would execute updater.exe from the install location with administrative privileges. Although the Mozilla Maintenance Service does ensure that updater.exe is signed by Mozilla, the version could have been rolled back to a previous version which would have allowed exploitation of an older bug and arbitrary code execution with system privileges.Note: This issue only affected Windows operating systems. Other operating systems are unaffected.

CVE-2020-15664: Attacker-induced prompt for extension installation
By holding a reference to the eval() function from an about:blank window, a malicious webpage could have gained access to the InstallTrigger object which would allow them to prompt the user to install an extension. Combined with user confusion, this could result in an unintended or malicious extension being installed.

CVE-2020-12401: Timing-attack on ECDSA signature generation
During ECDSA signature generation, padding applied in the nonce designed to ensure constant-time scalar multiplication was removed, resulting in variable-time execution dependent on secret data.

CVE-2020-6829: P-384 and P-521 vulnerable to an electro-magnetic side channel attack on signature generation
When performing EC scalar point multiplication, the wNAF point multiplication algorithm was used, which leaked partial information about the nonce used during signature generation. Given an electro-magnetic trace of a few signature generations, the private key could have been computed.

CVE-2020-12400: P-384 and P-521 vulnerable to a side channel attack on modular inversion
When converting coordinates from projective to affine, the modular inversion was not performed in constant time, resulting in a possible timing-based side channel attack.

CVE-2020-15665: Address bar not reset when choosing to stay on a page after the beforeunload dialog is shown
Firefox did not reset the address bar after the beforeunload dialog was shown if the user chose to remain on the page. This could have resulted in an incorrect URL being shown when used in conjunction with other unexpected browser behaviors.

CVE-2020-15666: MediaError message property leaks cross-origin response status
When trying to load a non-video in an audio/video context the exact status code (200, 302, 404, 500, 412, 403, etc.) was disclosed via the MediaError Message. This level of information leakage is inconsistent with the standardized onerror/onsuccess disclosure and can lead to inferring login status to services or device discovery on a local network among other attacks.

CVE-2020-15667: Heap overflow when processing an update file
When processing a MAR update file, after the signature has been validated, an invalid name length could result in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 80.");

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

if (version_is_less(version: version, test_version: "80")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "80", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
