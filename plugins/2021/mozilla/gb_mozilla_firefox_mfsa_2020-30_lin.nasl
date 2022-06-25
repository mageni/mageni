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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.30");
  script_cve_id("CVE-2020-15652", "CVE-2020-15653", "CVE-2020-15654", "CVE-2020-15655", "CVE-2020-15656", "CVE-2020-15657", "CVE-2020-15658", "CVE-2020-15659", "CVE-2020-6463", "CVE-2020-6514");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 12:15:00 +0000 (Tue, 18 Aug 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-30) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-30");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-30/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1550133%2C1633880%2C1638856%2C1643613%2C1644839%2C1645835%2C1646006%2C1646220%2C1646787%2C1649347%2C1650811%2C1651678");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1521542");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1634872");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1635293");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1637745");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1642792");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1644954");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1645204");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1647293");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1648333");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-15652: Potential leak of redirect targets when loading scripts in a worker
By observing the stack trace for JavaScript errors in web workers, it was possible to leak the result of a cross-origin redirect. This applied only to content that can be parsed as script.

CVE-2020-6514: WebRTC data channel leaks internal address to peer
WebRTC used the memory address of a class instance as a connection identifier.
Unfortunately, this value is often transmitted to the peer, which allows bypassing ASLR.

CVE-2020-15655: Extension APIs could be used to bypass Same-Origin Policy
Mozilla Developer Rob Wu discovered that a redirected HTTP request which is observed or modified through a web extension could bypass existing CORS checks, leading to potential disclosure of cross-origin information.

CVE-2020-15653: Bypassing iframe sandbox when allowing popups
Mozilla developer Anne van Kesteren discovered that <iframe sandbox> with the allow-popups flag could be bypassed when using noopener links. This could have led to security issues for websites relying on sandbox configurations that allowed popups and hosted arbitrary content.

CVE-2020-6463: Use-after-free in ANGLE gl::Texture::onUnbindAsSamplerTexture
Crafted media files could lead to a race in texture caches, resulting in a use-after-free, memory corruption, and a potentially exploitable crash.

CVE-2020-15656: Type confusion for special arguments in IonMonkey
JIT optimizations involving the Javascript arguments object could confuse later optimizations.
This risk was already mitigated by various precautions in the code, resulting in this bug rated at only moderate severity.

CVE-2020-15658: Overriding file type when saving to disk
The code for downloading files did not properly take care of special characters,
which led to an attacker being able to cut off the file ending at an earlier position, leading to a different file type being downloaded than shown in the dialog.

CVE-2020-15657: DLL hijacking due to incorrect loading path
Firefox could be made to load attacker-supplied DLL files from the installation directory.
This required an attacker that is already capable of placing files in the installation directory.
Note: This issue only affected Windows operating systems. Other operating systems are unaffected.

CVE-2020-15654: Custom cursor can overlay user interface
When in an endless loop, a website specifying a custom cursor using CSS could make it look like the user is interacting with the user interface, when they are not. This could lead to a perceived broken state, especially when interactions with existing browser dialogs and warnings do not work.

CVE-2020-15659: Memory safety bugs fixed in Firefox 79
Mozilla developers and community members Kevin Brosnan, Alexandru Michis, Natalia Csoregi, Jason Kratzer, Christian Holler, Simon Giesecke, Luke Wagner reported memory safety bugs present in Firefox 78. Some of ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"Firefox version(s) below 79.");

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

if (version_is_less(version: version, test_version: "79")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "79", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
