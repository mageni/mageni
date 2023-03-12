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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0399.1");
  script_cve_id("CVE-2022-39316", "CVE-2022-39317", "CVE-2022-39320", "CVE-2022-39347", "CVE-2022-41877");
  script_tag(name:"creation_date", value:"2023-02-14 04:19:30 +0000 (Tue, 14 Feb 2023)");
  script_version("2023-02-14T10:18:49+0000");
  script_tag(name:"last_modification", value:"2023-02-14 10:18:49 +0000 (Tue, 14 Feb 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-29 19:51:00 +0000 (Tue, 29 Nov 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0399-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0399-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230399-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2023:0399-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

CVE-2022-39316: Fixed out of bound read in zgfx decoder (bsc#1205512).

CVE-2022-39317: Fixed undefined behaviour in zgfx decoder (bsc#1205512).

CVE-2022-39320: Fixed heap buffer overflow in urbdrc channel
 (bsc#1205512).

CVE-2022-39347: Fixed missing path sanitation with drive channel
 (bsc#1205512).

CVE-2022-41877: Fixed missing input length validation in drive channel
 (bsc#1205512).");

  script_tag(name:"affected", value:"'freerdp' package(s) on SUSE Linux Enterprise Module for Packagehub Subpackages 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.4.0~150400.3.18.1", rls:"SLES15.0SP4"))) {
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
