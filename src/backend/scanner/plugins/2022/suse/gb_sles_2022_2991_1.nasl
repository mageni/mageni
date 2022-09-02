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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2991.1");
  script_cve_id("CVE-2021-46828");
  script_tag(name:"creation_date", value:"2022-09-02 04:52:13 +0000 (Fri, 02 Sep 2022)");
  script_version("2022-09-02T09:02:37+0000");
  script_tag(name:"last_modification", value:"2022-09-02 09:02:37 +0000 (Fri, 02 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-01 16:51:00 +0000 (Mon, 01 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2991-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2991-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222991-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtirpc' package(s) announced via the SUSE-SU-2022:2991-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libtirpc fixes the following issues:

CVE-2021-46828: Fixed an uncontrolled file descriptor consumption, which
 could be exploited by remote attackers to prevent applications using the
 library from accepting new connections (bsc#1201680).

Non-security fixes:

Exclude ipv6 addresses in client protocol version 2 code (bsc#1200800)

Fix memory leak in params.r_addr assignment (bsc#1198752)");

  script_tag(name:"affected", value:"'libtirpc' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-debugsource", rpm:"libtirpc-debugsource~1.0.2~150000.3.18.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-devel", rpm:"libtirpc-devel~1.0.2~150000.3.18.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-netconfig", rpm:"libtirpc-netconfig~1.0.2~150000.3.18.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3", rpm:"libtirpc3~1.0.2~150000.3.18.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-debuginfo", rpm:"libtirpc3-debuginfo~1.0.2~150000.3.18.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-debugsource", rpm:"libtirpc-debugsource~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-devel", rpm:"libtirpc-devel~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-netconfig", rpm:"libtirpc-netconfig~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3", rpm:"libtirpc3~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-32bit", rpm:"libtirpc3-32bit~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-32bit-debuginfo", rpm:"libtirpc3-32bit-debuginfo~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-debuginfo", rpm:"libtirpc3-debuginfo~1.0.2~150000.3.18.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-debugsource", rpm:"libtirpc-debugsource~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-devel", rpm:"libtirpc-devel~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc-netconfig", rpm:"libtirpc-netconfig~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3", rpm:"libtirpc3~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-32bit", rpm:"libtirpc3-32bit~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-32bit-debuginfo", rpm:"libtirpc3-32bit-debuginfo~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtirpc3-debuginfo", rpm:"libtirpc3-debuginfo~1.0.2~150000.3.18.1", rls:"SLES15.0SP2"))) {
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
