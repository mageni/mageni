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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2909.1");
  script_cve_id("CVE-2020-12825");
  script_tag(name:"creation_date", value:"2022-08-29 04:54:21 +0000 (Mon, 29 Aug 2022)");
  script_version("2022-08-29T04:54:21+0000");
  script_tag(name:"last_modification", value:"2022-08-29 04:54:21 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 18:15:00 +0000 (Tue, 08 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2909-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP3|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2909-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222909-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcroco' package(s) announced via the SUSE-SU-2022:2909-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libcroco fixes the following issues:

CVE-2020-12825: Fixed an uncontrolled recursion issue (bsc#1171685).");

  script_tag(name:"affected", value:"'libcroco' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3", rpm:"libcroco-0_6-3~0.6.11~12.6.45", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-32bit", rpm:"libcroco-0_6-3-32bit~0.6.11~12.6.45", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo", rpm:"libcroco-0_6-3-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo-32bit", rpm:"libcroco-0_6-3-debuginfo-32bit~0.6.11~12.6.45", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debuginfo", rpm:"libcroco-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debugsource", rpm:"libcroco-debugsource~0.6.11~12.6.45", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3", rpm:"libcroco-0_6-3~0.6.11~12.6.45", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-32bit", rpm:"libcroco-0_6-3-32bit~0.6.11~12.6.45", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo", rpm:"libcroco-0_6-3-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo-32bit", rpm:"libcroco-0_6-3-debuginfo-32bit~0.6.11~12.6.45", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debuginfo", rpm:"libcroco-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debugsource", rpm:"libcroco-debugsource~0.6.11~12.6.45", rls:"SLES12.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3", rpm:"libcroco-0_6-3~0.6.11~12.6.45", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-32bit", rpm:"libcroco-0_6-3-32bit~0.6.11~12.6.45", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo", rpm:"libcroco-0_6-3-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo-32bit", rpm:"libcroco-0_6-3-debuginfo-32bit~0.6.11~12.6.45", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debuginfo", rpm:"libcroco-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debugsource", rpm:"libcroco-debugsource~0.6.11~12.6.45", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3", rpm:"libcroco-0_6-3~0.6.11~12.6.45", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-32bit", rpm:"libcroco-0_6-3-32bit~0.6.11~12.6.45", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo", rpm:"libcroco-0_6-3-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-0_6-3-debuginfo-32bit", rpm:"libcroco-0_6-3-debuginfo-32bit~0.6.11~12.6.45", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debuginfo", rpm:"libcroco-debuginfo~0.6.11~12.6.45", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcroco-debugsource", rpm:"libcroco-debugsource~0.6.11~12.6.45", rls:"SLES12.0SP5"))) {
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
