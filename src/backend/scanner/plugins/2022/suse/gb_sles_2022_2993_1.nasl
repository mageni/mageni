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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2993.1");
  script_cve_id("CVE-2021-41159", "CVE-2021-41160");
  script_tag(name:"creation_date", value:"2022-09-05 04:57:00 +0000 (Mon, 05 Sep 2022)");
  script_version("2022-09-05T04:57:00+0000");
  script_tag(name:"last_modification", value:"2022-09-05 04:57:00 +0000 (Mon, 05 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-04 16:35:00 +0000 (Thu, 04 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2993-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2993-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222993-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2022:2993-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

Fixed two input validation issues (bsc#1191895):
 - CVE-2021-41159: Fixed an improper validation of client input for
 gateway connections.
 - CVE-2021-41160: Fixed improper region checks that could lead to memory
 corruption.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy-debuginfo", rpm:"freerdp-proxy-debuginfo~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2", rpm:"libwinpr2~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-debuginfo", rpm:"libwinpr2-debuginfo~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.4.0~150400.3.6.1", rls:"SLES15.0SP4"))) {
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
