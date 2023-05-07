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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1821.1");
  script_cve_id("CVE-2023-25193");
  script_tag(name:"creation_date", value:"2023-05-05 04:23:33 +0000 (Fri, 05 May 2023)");
  script_version("2023-05-05T09:09:19+0000");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-13 14:53:00 +0000 (Mon, 13 Feb 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1821-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2|SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1821-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231821-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'harfbuzz' package(s) announced via the SUSE-SU-2023:1821-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for harfbuzz fixes the following issues:

CVE-2023-25193: Fixed vulnerability that allowed attackers to trigger O(n^2) growth via consecutive marks (bsc#1207922).");

  script_tag(name:"affected", value:"'harfbuzz' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-debugsource", rpm:"harfbuzz-debugsource~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0", rpm:"libharfbuzz-icu0~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0-debuginfo", rpm:"libharfbuzz-icu0-debuginfo~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0", rpm:"libharfbuzz0~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-32bit", rpm:"libharfbuzz0-32bit~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo", rpm:"libharfbuzz0-debuginfo~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo-32bit", rpm:"libharfbuzz0-debuginfo-32bit~1.4.5~8.3.1", rls:"SLES12.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-debugsource", rpm:"harfbuzz-debugsource~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0", rpm:"libharfbuzz-icu0~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0-debuginfo", rpm:"libharfbuzz-icu0-debuginfo~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0", rpm:"libharfbuzz0~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-32bit", rpm:"libharfbuzz0-32bit~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo", rpm:"libharfbuzz0-debuginfo~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo-32bit", rpm:"libharfbuzz0-debuginfo-32bit~1.4.5~8.3.1", rls:"SLES12.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"harfbuzz-debugsource", rpm:"harfbuzz-debugsource~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0", rpm:"libharfbuzz-icu0~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz-icu0-debuginfo", rpm:"libharfbuzz-icu0-debuginfo~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0", rpm:"libharfbuzz0~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-32bit", rpm:"libharfbuzz0-32bit~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo", rpm:"libharfbuzz0-debuginfo~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libharfbuzz0-debuginfo-32bit", rpm:"libharfbuzz0-debuginfo-32bit~1.4.5~8.3.1", rls:"SLES12.0SP5"))) {
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
