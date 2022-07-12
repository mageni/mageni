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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0137");
  script_cve_id("CVE-2018-6358", "CVE-2018-7867", "CVE-2018-7868", "CVE-2018-7870", "CVE-2018-7871", "CVE-2018-7872", "CVE-2018-7875", "CVE-2018-9165");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2019-0137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0137");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0137.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=24505");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/DCVKRTMEAJTXCYXNA53WZFPDF67TN7NC/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ming' package(s) announced via the MGASA-2019-0137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The printDefineFont2 function (util/listfdb.c) in libming through 0.4.8 is
vulnerable to a heap-based buffer overflow, which may allow attackers to
cause a denial of service or unspecified other impact via a crafted FDB
file. (CVE-2018-6358)

There is a heap-based buffer overflow in the getString function of
util/decompile.c in libming 0.4.8 during a RegisterNumber sprintf. A
Crafted input will lead to a denial of service attack. (CVE-2018-7867)

There is a heap-based buffer over-read in the getName function of
util/decompile.c in libming 0.4.8 for CONSTANT8 data. A Crafted input will
lead to a denial of service attack. (CVE-2018-7868)

An invalid memory address dereference was discovered in getString in
util/decompile.c in libming 0.4.8 for CONSTANT16 data. The vulnerability
causes a segmentation fault and application crash, which leads to denial
of service. (CVE-2018-7870)

There is a heap-based buffer over-read in the getName function of
util/decompile.c in libming 0.4.8 for CONSTANT16 data. A crafted input
will lead to a denial of service or possibly unspecified other impact.
(CVE-2018-7871)

An invalid memory address dereference was discovered in the function
getName in libming 0.4.8 for CONSTANT16 data. The vulnerability causes a
segmentation fault and application crash, which leads to denial of
service. (CVE-2018-7872)

There is a heap-based buffer over-read in the getString function of
util/decompile.c in libming 0.4.8 for CONSTANT8 data. A Crafted input
will lead to a denial of service attack. (CVE-2018-7875)

The pushdup function in util/decompile.c in libming through 0.4.8 does
not recognize the need for ActionPushDuplicate to perform a deep copy
when a String is at the top of the stack, making the library vulnerable
to a util/decompile.c getName NULL pointer dereference, which may allow
attackers to cause a denial of service via a crafted SWF file.
(CVE-2018-9165)");

  script_tag(name:"affected", value:"'ming' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"lib64ming-devel", rpm:"lib64ming-devel~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ming1", rpm:"lib64ming1~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libming-devel", rpm:"libming-devel~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libming1", rpm:"libming1~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ming", rpm:"ming~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ming-utils", rpm:"ming-utils~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SWF", rpm:"perl-SWF~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-SWF", rpm:"python-SWF~0.4.9~0.git20181112.1.mga6", rls:"MAGEIA6"))) {
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
