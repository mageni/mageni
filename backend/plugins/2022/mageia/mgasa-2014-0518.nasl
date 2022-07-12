# Copyright (C) 2022 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0518");
  script_cve_id("CVE-2014-1587", "CVE-2014-1588", "CVE-2014-1589", "CVE-2014-1590", "CVE-2014-1591", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594", "CVE-2014-8631", "CVE-2014-8632");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-24 02:59:00 +0000 (Sat, 24 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2014-0518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0518");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0518.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14733");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-83/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-84/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-85/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-86/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-87/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-88/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-89/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2014-91/");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12978");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'iceape' package(s) announced via the MGASA-2014-0518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"When the oxygen-gtk was active and iceape tried to draw a menu (for
example after a mouse down event on the menu bar), a segmentation
fault was triggered causing iceape to crash. The oxygen-gtk theme
engine contains a solution for this problem, this is now enabled for
iceape. (MGA #12978)

Mozilla developers and community identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code. (CVE-2014-1587, CVE-2014-1588)

A method was found to trigger chrome level XML Binding Language (XBL)
bindings through web content. This was possible because some chrome
accessible CSS stylesheets had their primary namespace improperly
declared. When this occurred, it was possible to use these stylesheets
to manipulate XBL bindings, allowing web content to bypass security
restrictions. This issue was limited to a specific set of stylesheets.
(CVE-2014-1589)

In Iceape (seamonkey) before version 2.31, passing a JavaScript object
to XMLHttpRequest that mimics an input stream will result in a crash.
This crash is not exploitable and can only be used for denial of
service attacks. (CVE-2014-1590)

Content Security Policy (CSP) violation reports triggered by a
redirect did not remove path information as required by the CSP
specification in Iceape (seamonkey) 2.30. This potentially reveals
information about the redirect that would not otherwise be known to
the original site. This could be used by a malicious site to obtain
sensitive information such as usernames or single-sign-on tokens
encoded within the target URLs. (CVE-2014-1591)

In Iceape (seamonkey) before version 2.31, a use-after-free could be
created by triggering the creation of a second root element while
parsing HTML written to a document created with document.open(). This
leads to a potentially exploitable crash. (CVE-2014-1592)

A buffer overflow during the parsing of media content was found using
the Address Sanitizer tool. This leads to a potentially exploitable
crash. (CVE-2014-1593)

A bad casting from the BasicThebesLayer to BasicContainerLayer
resulted in undefined behavior. This behavior is potentially
exploitable with some compilers but no clear mechanism to trigger it
through web content was identified. (CVE-2014-1594)

When chrome objects are protected by Chrome Object Wrappers (COW) and
are passed as native interfaces, if this is done with some methods,
normally protected objects may be accessible to native methods exposed
to web content. (CVE-2014-8631)

When XrayWrappers filter object properties and validation of the
object initially occurs, one set of object properties will appear to
be available. Later, when the XrayWrappers are removed, a more
expansive set of properties is ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"iceape", rpm:"iceape~2.31~3.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
