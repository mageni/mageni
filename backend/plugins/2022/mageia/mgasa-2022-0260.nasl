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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0260");
  script_cve_id("CVE-2021-40391", "CVE-2021-40393", "CVE-2021-40394", "CVE-2021-40400", "CVE-2021-40401");
  script_tag(name:"creation_date", value:"2022-07-14 09:18:53 +0000 (Thu, 14 Jul 2022)");
  script_version("2022-07-14T09:18:53+0000");
  script_tag(name:"last_modification", value:"2022-07-14 09:18:53 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-31 18:27:00 +0000 (Tue, 31 May 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0260)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0260");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0260.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30622");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/TUM5GIUZJ7AVHVCXDZW6ZVCAPV2ISN47/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gerbv' package(s) announced via the MGASA-2022-0260 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An out-of-bounds write vulnerability exists in the drill format T-code
tool number functionality of Gerbv 2.7.0, dev (commit b5f1eacd), and the
forked version of Gerbv (commit 71493260). (CVE-2021-40391)

An out-of-bounds write vulnerability exists in the RS-274X aperture macro
variables handling functionality of Gerbv 2.7.0 and dev (commit b5f1eacd)
and the forked version of Gerbv (commit 71493260). (CVE-2021-40393,
CVE-2021-40394)

An out-of-bounds read vulnerability exists in the RS-274X aperture macro
outline primitive functionality of Gerbv 2.7.0 and dev (commit b5f1eacd)
and the forked version of Gerbv (commit d7f42a9a). (CVE-2021-40400)

A use-after-free vulnerability exists in the RS-274X aperture definition
tokenization functionality of Gerbv 2.7.0 and dev (commit b5f1eacd) and
Gerbv forked 2.7.1. (CVE-2021-40401)");

  script_tag(name:"affected", value:"'gerbv' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"gerbv", rpm:"gerbv~2.7.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gerbv-examples", rpm:"gerbv-examples~2.7.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gerbv-devel", rpm:"lib64gerbv-devel~2.7.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gerbv1", rpm:"lib64gerbv1~2.7.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgerbv-devel", rpm:"libgerbv-devel~2.7.3~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgerbv1", rpm:"libgerbv1~2.7.3~1.mga8", rls:"MAGEIA8"))) {
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
