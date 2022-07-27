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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0383");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2019-0383)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0383");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0383.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25816");
  script_xref(name:"URL", value:"https://openafs.org/pages/security/OPENAFS-SA-2019-001.txt");
  script_xref(name:"URL", value:"https://openafs.org/pages/security/OPENAFS-SA-2019-002.txt");
  script_xref(name:"URL", value:"https://openafs.org/pages/security/OPENAFS-SA-2019-003.txt");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2019-12/msg00013.html");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.8.4/RELNOTES-1.8.4");
  script_xref(name:"URL", value:"http://openafs.org/dl/openafs/1.8.5/RELNOTES-1.8.5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openafs' package(s) announced via the MGASA-2019-0383 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to security-release 1.8.5, addresses:

* OPENAFS-SA-2019-001: Skip server OUT args on error
* OPENAFS-SA-2019-002: Zero all server RPC args
* OPENAFS-SA-2019-003: ubik: Avoid unlocked ubik_currentTrans deref

Update to official version 1.8.4:

* support Linux-kernel 5.3
* Avoid non-dir ENOENT errors in afs_lookup
* fix parsing of fileservers with -vlruthresh, etc.
* other bugfixes");

  script_tag(name:"affected", value:"'openafs' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-static-devel", rpm:"lib64openafs-static-devel~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs2", rpm:"lib64openafs2~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-static-devel", rpm:"libopenafs-static-devel~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs2", rpm:"libopenafs2~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.8.5~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.8.5~1.mga7", rls:"MAGEIA7"))) {
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
