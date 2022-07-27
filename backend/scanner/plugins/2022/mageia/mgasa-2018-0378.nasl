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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0378");
  script_cve_id("CVE-2018-15908", "CVE-2018-15909", "CVE-2018-15910", "CVE-2018-15911", "CVE-2018-16509", "CVE-2018-16510", "CVE-2018-16511", "CVE-2018-16513", "CVE-2018-16539", "CVE-2018-16540", "CVE-2018-16541", "CVE-2018-16542", "CVE-2018-16543", "CVE-2018-16802");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0378)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0378");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0378.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23526");
  script_xref(name:"URL", value:"https://www.ghostscript.com/doc/9.24/History9.htm#Version9.24");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/09/05/3");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/09/06/3");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/09/09/1");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/09/09/2");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2018/09/11/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the MGASA-2018-0378 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated ghostscript packages fix several security vulnerabilities
including:

In Artifex Ghostscript 9.23 before 2018-08-23, attackers are able to supply
malicious PostScript files to bypass .tempfile restrictions and write files
(CVE-2018-15908).

In Artifex Ghostscript 9.23 before 2018-08-24, a type confusion using the
.shfill operator could be used by attackers able to supply crafted PostScript
files to crash the interpreter or potentially execute code (CVE-2018-15909).

In Artifex Ghostscript before 9.24, attackers able to supply crafted
PostScript files could use a type confusion in the LockDistillerParams
parameter to crash the interpreter or execute code (CVE-2018-15910).

In Artifex Ghostscript 9.23 before 2018-08-24, attackers able to supply
crafted PostScript could use uninitialized memory access in the aesdecode
operator to crash the interpreter or potentially execute code
(CVE-2018-15911).

An issue was discovered in Artifex Ghostscript before 9.24. Incorrect
'restoration of privilege' checking during handling of /invalidaccess
exceptions could be used by attackers able to supply crafted PostScript
to execute code using the 'pipe' instruction (CVE-2018-16509).

An issue was discovered in Artifex Ghostscript before 9.24. Incorrect exec
stack handling in the 'CS' and 'SC' PDF primitives could be used by remote
attackers able to supply crafted PDFs to crash the interpreter or possibly
have unspecified other impact (CVE-2018-16510).

An issue was discovered in Artifex Ghostscript before 9.24. A type
confusion in 'ztype' could be used by remote attackers able to supply
crafted PostScript to crash the interpreter or possibly have unspecified
other impact (CVE-2018-16511).

In Artifex Ghostscript before 9.24, attackers able to supply crafted
PostScript files could use a type confusion in the setcolor function to
crash the interpreter or possibly have unspecified other impact
(CVE-2018-16513).

In Artifex Ghostscript before 9.24, attackers able to supply crafted
PostScript files could use incorrect access checking in temp file handling
to disclose contents of files on the system otherwise not readable
(CVE-2018-16539).

In Artifex Ghostscript before 9.24, attackers able to supply crafted
PostScript files to the builtin PDF14 converter could use a use-after-free
in copydevice handling to crash the interpreter or possibly have unspecified
other impact (CVE-2018-16540).

In Artifex Ghostscript before 9.24, attackers able to supply crafted
PostScript files could use incorrect free logic in pagedevice replacement
to crash the interpreter (CVE-2018-16541).

In Artifex Ghostscript before 9.24, attackers able to supply crafted
PostScript files could use insufficient interpreter stack-size checking
during error handling to crash the interpreter (CVE-2018-16542).

In Artifex Ghostscript before 9.24, gssetresolution and gsgetresolution
allow attackers to have an unspecified ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Mageia 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~132.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~132.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.24~1.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~132.5.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~132.5.mga6", rls:"MAGEIA6"))) {
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
