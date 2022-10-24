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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3671.1");
  script_cve_id("CVE-2014-9862");
  script_tag(name:"creation_date", value:"2022-10-21 04:44:57 +0000 (Fri, 21 Oct 2022)");
  script_version("2022-10-21T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-10-21 10:20:04 +0000 (Fri, 21 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-17 14:15:00 +0000 (Thu, 17 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3671-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3671-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223671-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libostree' package(s) announced via the SUSE-SU-2022:3671-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libostree fixes the following issues:

CVE-2014-9862: Fixed arbitrary write on heap vulnerability (bsc#1201770).");

  script_tag(name:"affected", value:"'libostree' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libostree-1-1", rpm:"libostree-1-1~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-1-1-debuginfo", rpm:"libostree-1-1-debuginfo~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree", rpm:"libostree~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-debuginfo", rpm:"libostree-debuginfo~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-debugsource", rpm:"libostree-debugsource~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libostree-devel", rpm:"libostree-devel~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-OSTree-1_0", rpm:"typelib-1_0-OSTree-1_0~2018.1~150000.4.3.1", rls:"SLES15.0"))) {
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
