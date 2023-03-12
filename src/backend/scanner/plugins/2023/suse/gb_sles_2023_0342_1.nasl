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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0342.1");
  script_cve_id("CVE-2022-48281");
  script_tag(name:"creation_date", value:"2023-02-13 04:19:57 +0000 (Mon, 13 Feb 2023)");
  script_version("2023-02-13T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-02-13 10:09:19 +0000 (Mon, 13 Feb 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-01 19:16:00 +0000 (Wed, 01 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0342-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP1|SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0342-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230342-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2023:0342-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tiff fixes the following issues:

CVE-2022-48281: Fixed a buffer overflow that could be triggered via a
 crafted image (bsc#1207413).");

  script_tag(name:"affected", value:"'tiff' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Micro 5.2, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Realtime Extension 15-SP3, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP3, SUSE Manager Proxy 4.2, SUSE Manager Retail Branch Server 4.2, SUSE Manager Server 4.2.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff", rpm:"tiff~4.0.9~150000.45.25.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~150000.45.25.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~150000.45.25.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit", rpm:"libtiff5-32bit~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-32bit-debuginfo", rpm:"libtiff5-32bit-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5", rpm:"libtiff5~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libtiff5-debuginfo", rpm:"libtiff5-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debuginfo", rpm:"tiff-debuginfo~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tiff-debugsource", rpm:"tiff-debugsource~4.0.9~150000.45.25.1", rls:"SLES15.0SP3"))) {
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
