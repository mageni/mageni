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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.1714.1");
  script_cve_id("CVE-2023-28100", "CVE-2023-28101");
  script_tag(name:"creation_date", value:"2023-04-03 04:21:51 +0000 (Mon, 03 Apr 2023)");
  script_version("2023-04-20T10:42:24+0000");
  script_tag(name:"last_modification", value:"2023-04-20 10:42:24 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-18 13:37:00 +0000 (Tue, 18 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:1714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:1714-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20231714-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak' package(s) announced via the SUSE-SU-2023:1714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for flatpak fixes the following issues:

CVE-2023-28101: Fixed misleading terminal output with metadata with ANSI control codes (bsc#1209410).
CVE-2023-28100: Fixed unsandboxed TIOCLINUX commands (bsc#1209411).

Update to version 1.10.8:

If an app update is blocked by parental controls policies,
 clean up the temporary deploy directory Fix Autotools build with versions of gpgme that no longer
 provide gpgme-config(1)
Fix regressions in flatpak history since 1.9.1 Don't display the appstream branch used internally Don't display temporary repositories used internally Ignore transaction log entries with empty REF field Warn instead of failing if other non-app, non-runtime refs are found Don't set up an unnecessary polkit agent for flatpak history Add test coverage Fix a typo in an error message Fix incorrect year in NEWS for 1.10.7 release Translation update: pl Add test coverage for Flatpak's seccomp filters");

  script_tag(name:"affected", value:"'flatpak' package(s) on SUSE Enterprise Storage 7, SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Real Time 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debuginfo", rpm:"flatpak-debuginfo~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debugsource", rpm:"flatpak-debugsource~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-devel", rpm:"flatpak-devel~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-zsh-completion", rpm:"flatpak-zsh-completion~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0-debuginfo", rpm:"libflatpak0-debuginfo~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-flatpak", rpm:"system-user-flatpak~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Flatpak-1_0", rpm:"typelib-1_0-Flatpak-1_0~1.10.8~150200.4.15.1", rls:"SLES15.0SP2"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"flatpak", rpm:"flatpak~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debuginfo", rpm:"flatpak-debuginfo~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-debugsource", rpm:"flatpak-debugsource~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-devel", rpm:"flatpak-devel~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flatpak-zsh-completion", rpm:"flatpak-zsh-completion~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0", rpm:"libflatpak0~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libflatpak0-debuginfo", rpm:"libflatpak0-debuginfo~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"system-user-flatpak", rpm:"system-user-flatpak~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Flatpak-1_0", rpm:"typelib-1_0-Flatpak-1_0~1.10.8~150200.4.15.1", rls:"SLES15.0SP3"))) {
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
