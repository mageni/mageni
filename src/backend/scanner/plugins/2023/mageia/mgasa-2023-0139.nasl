# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0139");
  script_cve_id("CVE-2022-0670", "CVE-2022-3650");
  script_tag(name:"creation_date", value:"2023-04-17 04:13:02 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-17T10:09:22+0000");
  script_tag(name:"last_modification", value:"2023-04-17 10:09:22 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-01 16:40:00 +0000 (Mon, 01 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0139)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0139");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0139.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30677");
  script_xref(name:"URL", value:"https://docs.ceph.com/en/latest/security/CVE-2022-0670/");
  script_xref(name:"URL", value:"https://github.com/ceph/ceph/pull/48713/commits");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph' package(s) announced via the MGASA-2023-0139 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Openstack manilla owning a Ceph File system 'share', enables the owner to
read/write any manilla share or entire file system. The vulnerability is
due to a bug in the 'volumes' plugin in Ceph Manager. This allows an
attacker to compromise Confidentiality and Integrity of a file system.
(CVE-2022-0670)
Privilege escalation and privileged information disclosure (CVE-2022-3650)");

  script_tag(name:"affected", value:"'ceph' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"ceph", rpm:"ceph~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-fuse", rpm:"ceph-fuse~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-immutable-object-cache", rpm:"ceph-immutable-object-cache~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mds", rpm:"ceph-mds~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mgr", rpm:"ceph-mgr~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-mon", rpm:"ceph-mon~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-osd", rpm:"ceph-osd~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-radosgw", rpm:"ceph-radosgw~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ceph-rbd", rpm:"ceph-rbd~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ceph-devel", rpm:"lib64ceph-devel~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ceph2", rpm:"lib64ceph2~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rados-devel", rpm:"lib64rados-devel~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rados2", rpm:"lib64rados2~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosgw-devel", rpm:"lib64radosgw-devel~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosgw2", rpm:"lib64radosgw2~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosstriper-devel", rpm:"lib64radosstriper-devel~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64radosstriper1", rpm:"lib64radosstriper1~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rbd-devel", rpm:"lib64rbd-devel~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rbd1", rpm:"lib64rbd1~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rgw-devel", rpm:"lib64rgw-devel~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64rgw2", rpm:"lib64rgw2~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ceph", rpm:"python3-ceph~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rados", rpm:"python3-rados~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rbd", rpm:"python3-rbd~15.2.17~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-rgw", rpm:"python3-rgw~15.2.17~1.mga8", rls:"MAGEIA8"))) {
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
