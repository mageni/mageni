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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0344");
  script_cve_id("CVE-2020-16287", "CVE-2020-16288", "CVE-2020-16289", "CVE-2020-16290", "CVE-2020-16291", "CVE-2020-16292", "CVE-2020-16293", "CVE-2020-16294", "CVE-2020-16295", "CVE-2020-16296", "CVE-2020-16297", "CVE-2020-16298", "CVE-2020-16299", "CVE-2020-16300", "CVE-2020-16301", "CVE-2020-16302", "CVE-2020-16303", "CVE-2020-16304", "CVE-2020-16305", "CVE-2020-16306", "CVE-2020-16307", "CVE-2020-16308", "CVE-2020-16309", "CVE-2020-16310", "CVE-2020-17538");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-31 21:15:00 +0000 (Mon, 31 Aug 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0344");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0344.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27169");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2335");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the MGASA-2020-0344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:

A buffer overflow vulnerability in lprn_is_black() in contrib/lips4/gdevlprn.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16287)

A buffer overflow vulnerability in pj_common_print_page() in devices/gdevpjet.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16288)

A buffer overflow vulnerability in cif_print_page() in devices/gdevcif.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16289)

A buffer overflow vulnerability in jetp3852_print_page() in devices/gdev3852.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16290)

A buffer overflow vulnerability in contrib/gdevdj9.c of Artifex Software
GhostScript v9.50 allows a remote attacker to cause a denial of service via
a crafted PDF file. (CVE-2020-16291)

A buffer overflow vulnerability in mj_raster_cmd() in contrib/japanese/gdevmjc.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16292)

A null pointer dereference vulnerability in
compose_group_nonknockout_nonblend_isolated_allmask_common()
in base/gxblend.c of Artifex Software GhostScript v9.50 allows a remote
attacker to cause a denial of service via a crafted PDF file. (CVE-2020-16293)

A buffer overflow vulnerability in epsc_print_page() in devices/gdevepsc.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16294)

A null pointer dereference vulnerability in clj_media_size() in devices/gdevclj.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16295)

A buffer overflow vulnerability in GetNumWrongData() in contrib/lips4/gdevlips.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16296)

A buffer overflow vulnerability in FloydSteinbergDitheringC() in contrib/gdevbjca.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16297)

A buffer overflow vulnerability in mj_color_correct() in contrib/japanese/gdevmjc.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16298)

A Division by Zero vulnerability in bj10v_print_page() in contrib/japanese/gdev10v.c
of Artifex Software GhostScript v9.50 allows a remote attacker to cause
a denial of service via a crafted PDF file. (CVE-2020-16299)

A buffer overflow vulnerability in tiff12_print_page() in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-X", rpm:"ghostscript-X~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-common", rpm:"ghostscript-common~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-doc", rpm:"ghostscript-doc~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-dvipdf", rpm:"ghostscript-dvipdf~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-module-X", rpm:"ghostscript-module-X~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs-devel", rpm:"lib64gs-devel~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gs9", rpm:"lib64gs9~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs-devel", rpm:"lib64ijs-devel~0.35~147.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ijs1", rpm:"lib64ijs1~0.35~147.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs-devel", rpm:"libgs-devel~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgs9", rpm:"libgs9~9.27~1.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs-devel", rpm:"libijs-devel~0.35~147.6.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libijs1", rpm:"libijs1~0.35~147.6.mga7", rls:"MAGEIA7"))) {
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
