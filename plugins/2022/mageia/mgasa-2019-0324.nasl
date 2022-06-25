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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0324");
  script_cve_id("CVE-2019-8625", "CVE-2019-8674", "CVE-2019-8707", "CVE-2019-8710", "CVE-2019-8719", "CVE-2019-8720", "CVE-2019-8726", "CVE-2019-8733", "CVE-2019-8735", "CVE-2019-8743", "CVE-2019-8763", "CVE-2019-8764", "CVE-2019-8765", "CVE-2019-8766", "CVE-2019-8768", "CVE-2019-8769", "CVE-2019-8771", "CVE-2019-8782", "CVE-2019-8783", "CVE-2019-8808", "CVE-2019-8811", "CVE-2019-8812", "CVE-2019-8813", "CVE-2019-8814", "CVE-2019-8815", "CVE-2019-8816", "CVE-2019-8819", "CVE-2019-8820", "CVE-2019-8821", "CVE-2019-8822", "CVE-2019-8823");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-15 07:15:00 +0000 (Sun, 15 Mar 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0324)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0324");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0324.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25657");
  script_xref(name:"URL", value:"https://webkitgtk.org/2019/09/09/webkitgtk2.26.0-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2019/09/23/webkitgtk2.26.1-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/2019/11/06/webkitgtk2.26.2-released.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2019-0005.html");
  script_xref(name:"URL", value:"https://webkitgtk.org/security/WSA-2019-0006.html");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/10/29/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2' package(s) announced via the MGASA-2019-0324 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated webkit2 packages fix security vulnerabilities:

Processing maliciously crafted web content may lead to universal cross
site scripting (CVE-2019-8625, CVE-2019-8674, CVE-2019-8719, CVE-2019-8813)

Processing maliciously crafted web content may lead to arbitrary code
execution (CVE-2019-8707, CVE-2019-8710, CVE-2019-8720, CVE-2019-8726,
CVE-2019-8733, CVE-2019-8735, CVE-2019-8743, CVE-2019-8763, CVE-2019-8764,
CVE-2019-8765, CVE-2019-8766, CVE-2019-8782, CVE-2019-8783, CVE-2019-8808,
CVE-2019-8811, CVE-2019-8812, CVE-2019-8814, CVE-2019-8815, CVE-2019-8816,
CVE-2019-8819, CVE-2019-8820, CVE-2019-8821, CVE-2019-8822, CVE-2019-8823)

A user may be unable to delete browsing history items (CVE-2019-8768)

Visiting a maliciously crafted website may reveal browsing history
(CVE-2019-8769)

Maliciously crafted web content may violate iframe sandboxing policy
(CVE-2019-8771)");

  script_tag(name:"affected", value:"'webkit2' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcore-gir4.0", rpm:"lib64javascriptcore-gir4.0~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64javascriptcoregtk4.0_18", rpm:"lib64javascriptcoregtk4.0_18~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2-devel", rpm:"lib64webkit2-devel~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk-gir4.0", rpm:"lib64webkit2gtk-gir4.0~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64webkit2gtk4.0_37", rpm:"lib64webkit2gtk4.0_37~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcore-gir4.0", rpm:"libjavascriptcore-gir4.0~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk4.0_18", rpm:"libjavascriptcoregtk4.0_18~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2-devel", rpm:"libwebkit2-devel~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk-gir4.0", rpm:"libwebkit2gtk-gir4.0~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebkit2gtk4.0_37", rpm:"libwebkit2gtk4.0_37~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2", rpm:"webkit2~2.26.2~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"webkit2-jsc", rpm:"webkit2-jsc~2.26.2~1.mga7", rls:"MAGEIA7"))) {
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
