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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1925.1");
  script_cve_id("CVE-2018-6952", "CVE-2019-13636");
  script_tag(name:"creation_date", value:"2022-06-03 04:18:28 +0000 (Fri, 03 Jun 2022)");
  script_version("2022-06-03T04:18:28+0000");
  script_tag(name:"last_modification", value:"2022-06-07 09:57:21 +0000 (Tue, 07 Jun 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-24 17:15:00 +0000 (Wed, 24 Jul 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1925-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1925-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221925-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the SUSE-SU-2022:1925-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for patch fixes the following issues:

Security issues fixed:

CVE-2019-13636: Fixed follow symlinks unless --follow-symlinks is given.
 This increases the security against malicious patches (bsc#1142041).

CVE-2018-6952: Fixed swapping fakelines in pch_swap. This bug was
 causing a double free leading to a crash (bsc#1080985).

Bugfixes:

Abort when cleaning up fails. This bug could cause an infinite loop when
 a patch wouldn't apply, leading to a segmentation fault (bsc#1111572).

Pass the correct stat to backup files. This bug would occasionally cause
 backup files to be missing when all hunks failed to apply (bsc#1198106).");

  script_tag(name:"affected", value:"'patch' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.6~150000.5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"patch-debuginfo", rpm:"patch-debuginfo~2.7.6~150000.5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"patch-debugsource", rpm:"patch-debugsource~2.7.6~150000.5.3.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.6~150000.5.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"patch-debuginfo", rpm:"patch-debuginfo~2.7.6~150000.5.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"patch-debugsource", rpm:"patch-debugsource~2.7.6~150000.5.3.1", rls:"SLES15.0SP4"))) {
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
