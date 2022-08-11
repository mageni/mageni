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
  script_oid("1.3.6.1.4.1.25623.1.2.1.2020.45");
  script_cve_id("CVE-2020-15254", "CVE-2020-15680", "CVE-2020-15681", "CVE-2020-15682", "CVE-2020-15683", "CVE-2020-15684", "CVE-2020-15969");
  script_tag(name:"creation_date", value:"2021-11-08 15:21:25 +0000 (Mon, 08 Nov 2021)");
  script_version("2021-11-08T15:21:25+0000");
  script_tag(name:"last_modification", value:"2021-11-15 10:55:03 +0000 (Mon, 15 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-28 14:13:00 +0000 (Wed, 28 Oct 2020)");

  script_name("Mozilla Firefox Security Advisory (MFSA2020-45) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("mozilla/firefox/linux/detected");

  script_xref(name:"Advisory-ID", value:"MFSA2020-45");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-45/");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1576843%2C1656987%2C1660954%2C1662760%2C1663439%2C1666140");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/buglist.cgi?bug_id=1653764%2C1661402%2C1662259%2C1664257");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1636654");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1658881");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1666568");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1666570");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1668514");
  script_xref(name:"URL", value:"https://github.com/crossbeam-rs/crossbeam/security/advisories/GHSA-v5m7-53cv-f3hx");
  script_xref(name:"URL", value:"https://github.com/sctplab/usrsctp/commit/ffed0925f27d404173c1e3e750d818f432d2c019");

  script_tag(name:"summary", value:"This host is missing a security update for Mozilla Firefox.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2020-15969: Use-after-free in usersctp
A use-after-free bug in the usersctp library was reported upstream. We assume this could have led to memory corruption and a potentially exploitable crash.

CVE-2020-15254: Undefined behavior in bounded channel of crossbeam rust crate
In the crossbeam rust crate, the bounded channel incorrectly assumed that Vec::from_iter had allocated capacity that was the same as the number of iterator elements. Vec::from_iter does not actually guarantee that and may allocate extra memory. The destructor of the bounded channel reconstructs Vec from the raw pointer based on the incorrect assumptions - this is unsound and caused a deallocation with the incorrect capacity when Vec::from_iter had allocated different sizes than the number of iterator elements. The impact on Firefox is undetermined, but in another use case, the behavior was causing corruption of jemalloc structures.

CVE-2020-15680: Presence of external protocol handlers could be determined through image tags
If a valid external protocol handler was referenced in an image tag, the resulting broken image size could be distinguished from a broken image size of a non-existent protocol handler. This allowed an attacker to successfully probe whether an external protocol handler was registered.

CVE-2020-15681: Multiple WASM threads may have overwritten each others' stub table entries
When multiple WASM threads had a reference to a module, and were looking up exported functions, one WASM thread could have overwritten another's entry in a shared stub table, resulting in a potentially exploitable crash.

CVE-2020-15682: The domain associated with the prompt to open an external protocol could be spoofed to display the incorrect origin
When a link to an external protocol was clicked, a prompt was presented that allowed the user to choose what application to open it in. An attacker could induce that prompt to be associated with an origin they didn't control, resulting in a spoofing attack. This was fixed by changing external protocol prompts to be tab-modal while also ensuring they could not be incorrectly associated with a different origin.

CVE-2020-15683: Memory safety bugs fixed in Firefox 82 and Firefox ESR 78.4
Mozilla developers and community members Simon Giesecke, Christian Holler, Philipp, and Jason Kratzer reported memory safety bugs present in Firefox 81 and Firefox ESR 78.3. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.

CVE-2020-15684: Memory safety bugs fixed in Firefox 82
Mozilla developers Christian Holler, Sebastian Hengst, Bogdan Tara, and Tyson Smith reported memory safety bugs present in Firefox 81. Some of these bugs showed evidence of memory corruption and we presume that with enough effort some of these could have been exploited to run arbitrary code.");

  script_tag(name:"affected", value:"Firefox version(s) below 82.");

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

if (version_is_less(version: version, test_version: "82")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "82", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
