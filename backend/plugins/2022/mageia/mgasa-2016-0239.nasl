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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0239");
  script_cve_id("CVE-2015-8934", "CVE-2016-4300", "CVE-2016-4301", "CVE-2016-4302");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0239)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0239");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0239.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18769");
  script_xref(name:"URL", value:"https://github.com/libarchive/libarchive/issues/521");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0152");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0153");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0154");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1349229");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1348439");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1348441");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1348444");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/06/23/6");
  script_xref(name:"URL", value:"https://groups.google.com/forum/#!msg/libarchive-discuss/sui01WaM3ic/WhAgI4ylAwAJ");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/06/24/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the MGASA-2016-0239 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out of bounds read in the rar parser: invalid read in function
copy_from_lzss_window() when unpacking malformed rar (CVE-2015-8934).

An exploitable heap overflow vulnerability exists in the 7zip
read_SubStreamsInfo functionality of libarchive. A specially crafted 7zip
file can cause a integer overflow resulting in memory corruption that can
lead to code execution. An attacker can send a malformed file to trigger
this vulnerability (CVE-2016-4300).

An exploitable stack based buffer overflow vulnerability exists in the
mtree parse_device functionality of libarchive. A specially crafted mtree
file can cause a buffer overflow resulting in memory corruption/code
execution. An attacker can send a malformed file to trigger this
vulnerability (CVE-2016-4301).

An exploitable heap overflow vulnerability exists in the Rar decompression
functionality of libarchive. A specially crafted Rar file can cause a heap
corruption eventually leading to code execution. An attacker can send a
malformed file to trigger this vulnerability (CVE-2016-4302).

A signed integer overflow in iso parser: integer overflow when computing
location of volume descriptor (CVE-2016-5844).

The libarchive package has been updated to version 3.2.1, fixing those
issues and other bugs.");

  script_tag(name:"affected", value:"'libarchive' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"bsdcat", rpm:"bsdcat~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdcpio", rpm:"bsdcpio~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive-devel", rpm:"lib64archive-devel~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64archive13", rpm:"lib64archive13~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive", rpm:"libarchive~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.2.1~1.mga5", rls:"MAGEIA5"))) {
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
