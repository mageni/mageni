# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2023.05");
  script_cve_id("CVE-2023-0767", "CVE-2023-25728", "CVE-2023-25729", "CVE-2023-25730", "CVE-2023-25731", "CVE-2023-25732", "CVE-2023-25733", "CVE-2023-25735", "CVE-2023-25736", "CVE-2023-25737", "CVE-2023-25739", "CVE-2023-25740", "CVE-2023-25741", "CVE-2023-25742", "CVE-2023-25744", "CVE-2023-25745");
  script_tag(name:"creation_date", value:"2023-02-15 11:24:57 +0000 (Wed, 15 Feb 2023)");
  script_version("2023-02-16T10:08:32+0000");
  script_tag(name:"last_modification", value:"2023-02-16 10:08:32 +0000 (Thu, 16 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Mozilla Firefox Security Advisory (MFSA2023-05) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2023-05");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-05/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1688592%2C1797186%2C1804998%2C1806521%2C1813284");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1789449%2C1803628%2C1810536");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1437126");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1790345");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1792138");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1794622");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1801542");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1804564");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1804640");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1808632");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1810711");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811331");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811464");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1811939");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1812611");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1813376");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1813424");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-25728: Content security policy leak in violation reports using iframes
The Content-Security-Policy-Report-Only header could allow an attacker to leak a child iframe's unredacted URI when interaction with that iframe triggers a redirect.

CVE-2023-25730: Screen hijack via browser fullscreen mode
A background script invoking requestFullscreen and then blocking the main thread could force the browser into fullscreen mode indefinitely, resulting in potential user confusion or spoofing attacks.

CVE-2023-0767: Arbitrary memory write via PKCS 12 in NSS
An attacker could construct a PKCS 12 cert bundle in such a way that could allow for arbitrary memory writes via PKCS 12 Safe Bag attributes being mishandled.

CVE-2023-25735: Potential use-after-free from compartment mismatch in SpiderMonkey
Cross-compartment wrappers wrapping a scripted proxy could have caused objects from other compartments to be stored in the main compartment resulting in a use-after-free after unwrapping the proxy.

CVE-2023-25737: Invalid downcast in SVGUtils::SetupStrokeGeometry
An invalid downcast from nsTextNode to SVGElement could have lead to undefined behavior.

CVE-2023-25739: Use-after-free in mozilla::dom::ScriptLoadContext::~ScriptLoadContext
Module load requests that failed were not being checked as to whether or not they were cancelled causing a use-after-free in ScriptLoadContext.

CVE-2023-25729: Extensions could have opened external schemes without user knowledge
Permission prompts for opening external schemes were only shown for ContentPrincipals resulting in extensions being able to open them without user interaction via ExpandedPrincipals. This could lead to further malicious actions such as downloading files or interacting with software already installed on the system.

CVE-2023-25732: Out of bounds memory write from EncodeInputStream
When encoding data from an inputStream in xpcom the size of the input being encoded was not correctly calculated potentially leading to an out of bounds memory write.

... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 110.");

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

if (version_is_less(version: version, test_version: "110")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "110", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
