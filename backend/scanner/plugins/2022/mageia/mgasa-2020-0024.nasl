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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0024");
  script_cve_id("CVE-2019-12790", "CVE-2019-12802", "CVE-2019-12865", "CVE-2019-14745");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-16 05:15:00 +0000 (Tue, 16 Jul 2019)");

  script_name("Mageia: Security Advisory (MGASA-2020-0024)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0024");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0024.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25933");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/ED2UIZ5J7YYFFA2MPSMJ543U3DPEREVZ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/IEXZWAMVKGZKHALV4IVWQS2ORJKRH57U/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RQO7V37RGQEKZDLY2JYKDZTLNN2YUBC5/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/PXQ6KYP4UMNSCJYHFT4TBIXLR2325SNS/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'radare2, radare2-cutter' package(s) announced via the MGASA-2020-0024 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated radare2 packages fix security vulnerabilities:

In radare2 through 3.5.1, there is a heap-based buffer over-read in the
r_egg_lang_parsechar function of egg_lang.c. This allows remote attackers
to cause a denial of service (application crash) or possibly have
unspecified other impact because of missing length validation in
libr/egg/egg.c (CVE-2019-12790).

In radare2 through 3.5.1, the rcc_context function of libr/egg/egg_lang.c
mishandles changing context. This allows remote attackers to cause a denial
of service (application crash) or possibly have unspecified other impact
(invalid memory access in r_egg_lang_parsechar, invalid free in rcc_pusharg)
(CVE-2019-12802).

In radare2 through 3.5.1, cmd_mount in libr/core/cmd_mount.c has a double
free for the ms command (CVE-2019-12865).

By using a crafted executable file, it's possible to execute arbitrary
shell commands with the permissions of the victim. This vulnerability is
due to improper handling of symbol names embedded in executables
(CVE-2019-14745).

The radare2 package has been updated to version 3.9.0, fixing these issues
and other bugs.

Also, the radare2-cutter package has been updated to version 1.9.0.");

  script_tag(name:"affected", value:"'radare2, radare2-cutter' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2-devel", rpm:"lib64radare2-devel~3.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radare2_3.9.0", rpm:"lib64radare2_3.9.0~3.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2-devel", rpm:"libradare2-devel~3.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libradare2_3.9.0", rpm:"libradare2_3.9.0~3.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2", rpm:"radare2~3.9.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"radare2-cutter", rpm:"radare2-cutter~1.9.0~1.1.mga7", rls:"MAGEIA7"))) {
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
