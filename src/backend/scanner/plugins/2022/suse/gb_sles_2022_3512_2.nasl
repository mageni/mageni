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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3512.2");
  script_cve_id("CVE-2021-28861");
  script_tag(name:"creation_date", value:"2022-10-18 04:52:04 +0000 (Tue, 18 Oct 2022)");
  script_version("2022-10-18T10:13:37+0000");
  script_tag(name:"last_modification", value:"2022-10-18 10:13:37 +0000 (Tue, 18 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-25 02:15:00 +0000 (Thu, 25 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3512-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3512-2");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223512-2/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the SUSE-SU-2022:3512-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python fixes the following issues:

CVE-2021-28861: Fixed an open redirection vulnerability in the HTTP
 server when an URI path starts with // (bsc#1202624).");

  script_tag(name:"affected", value:"'python' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo", rpm:"libpython2_7-1_0-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo", rpm:"python-base-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debugsource", rpm:"python-base-debugsource~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses-debuginfo", rpm:"python-curses-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debugsource", rpm:"python-debugsource~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm-debuginfo", rpm:"python-gdbm-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk-debuginfo", rpm:"python-tk-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml-debuginfo", rpm:"python-xml-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo", rpm:"libpython2_7-1_0-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo", rpm:"python-base-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debugsource", rpm:"python-base-debugsource~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses-debuginfo", rpm:"python-curses-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debugsource", rpm:"python-debugsource~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm-debuginfo", rpm:"python-gdbm-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk-debuginfo", rpm:"python-tk-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml-debuginfo", rpm:"python-xml-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-debuginfo", rpm:"libpython2_7-1_0-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debuginfo", rpm:"python-base-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-debugsource", rpm:"python-base-debugsource~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses-debuginfo", rpm:"python-curses-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debuginfo", rpm:"python-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-debugsource", rpm:"python-debugsource~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm-debuginfo", rpm:"python-gdbm-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk-debuginfo", rpm:"python-tk-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml-debuginfo", rpm:"python-xml-debuginfo~2.7.18~150000.44.1", rls:"SLES15.0SP2"))) {
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
