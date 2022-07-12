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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0515");
  script_cve_id("CVE-2014-0159", "CVE-2014-2852", "CVE-2014-4044");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-08-24 15:32:00 +0000 (Wed, 24 Aug 2016)");

  script_name("Mageia: Security Advisory (MGASA-2014-0515)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0515");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0515.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13188");
  script_xref(name:"URL", value:"http://www.openafs.org/security/OPENAFS-SA-2014-001.txt");
  script_xref(name:"URL", value:"http://www.openafs.org/security/OPENAFS-SA-2014-002.txt");
  script_xref(name:"URL", value:"http://www.openafs.org/dl/openafs/1.6.7/RELNOTES-1.6.6");
  script_xref(name:"URL", value:"http://www.openafs.org/dl/openafs/1.6.7/RELNOTES-1.6.7");
  script_xref(name:"URL", value:"http://www.openafs.org/dl/openafs/1.6.7/RELNOTES-1.6.8");
  script_xref(name:"URL", value:"http://www.openafs.org/dl/openafs/1.6.9/RELNOTES-1.6.9");
  script_xref(name:"URL", value:"http://www.openafs.org/dl/openafs/1.6.7/RELNOTES-1.6.10");
  script_xref(name:"URL", value:"https://lists.openafs.org/pipermail/openafs-announce/2014/000455.html");
  script_xref(name:"URL", value:"https://lists.openafs.org/pipermail/openafs-announce/2014/000460.html");
  script_xref(name:"URL", value:"https://lists.openafs.org/pipermail/openafs-announce/2014/000467.html");
  script_xref(name:"URL", value:"https://lists.openafs.org/pipermail/openafs-announce/2014/000468.html");
  script_xref(name:"URL", value:"https://lists.openafs.org/pipermail/openafs-announce/2014/000472.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2899");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openafs' package(s) announced via the MGASA-2014-0515 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated openafs packages fix security vulnerabilities:

Buffer overflow in the GetStatistics64 remote procedure call (RPC) in OpenAFS
before 1.6.7 allows remote attackers to cause a denial of service (crash) via
a crafted statsVersion argument (CVE-2014-0159).

OpenAFS before 1.6.7 delays the listen thread when an RXS_CheckResponse fails,
which allows remote attackers to cause a denial of service (performance
degradation) via an invalid packet (CVE-2014-2852).

OpenAFS 1.6.8 does not properly clear the fields in the host structure, which
allows remote attackers to cause a denial of service (uninitialized memory
access and crash) via unspecified vectors related to TMAY requests
(CVE-2014-4044).

The OpenAFS package has been updated to version 1.6.10, fixing these issues
and other bugs, as well as providing support for newer kernel versions.");

  script_tag(name:"affected", value:"'openafs' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"dkms-libafs", rpm:"dkms-libafs~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-devel", rpm:"lib64openafs-devel~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs-static-devel", rpm:"lib64openafs-static-devel~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64openafs1", rpm:"lib64openafs1~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-devel", rpm:"libopenafs-devel~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs-static-devel", rpm:"libopenafs-static-devel~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenafs1", rpm:"libopenafs1~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs", rpm:"openafs~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-client", rpm:"openafs-client~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-doc", rpm:"openafs-doc~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openafs-server", rpm:"openafs-server~1.6.10~1.1.mga4", rls:"MAGEIA4"))) {
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
