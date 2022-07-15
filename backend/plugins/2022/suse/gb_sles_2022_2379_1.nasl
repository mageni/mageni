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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2379.1");
  script_cve_id("CVE-2017-16525", "CVE-2021-26341", "CVE-2021-4157", "CVE-2022-1679", "CVE-2022-20132", "CVE-2022-20141", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-33981");
  script_tag(name:"creation_date", value:"2022-07-13 15:07:04 +0000 (Wed, 13 Jul 2022)");
  script_version("2022-07-13T15:07:04+0000");
  script_tag(name:"last_modification", value:"2022-07-13 15:07:04 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-07 15:31:00 +0000 (Thu, 07 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2379-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2379-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222379-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2379-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP2 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-29900, CVE-2022-29901: Fixed the RETBLEED attack, a new Spectre
 like Branch Target Buffer attack, that can leak arbitrary kernel
 information (bsc#1199657).

CVE-2022-1679: Fixed a use-after-free in the Atheros wireless driver in
 the way a user forces the ath9k_htc_wait_for_target function to fail
 with some input messages (bsc#1199487).

CVE-2022-20132: Fixed out of bounds read due to improper input
 validation in lg_probe and related functions of hid-lg.c (bsc#1200619).

CVE-2022-33981: Fixed use-after-free in floppy driver (bsc#1200692)

CVE-2022-20141: Fixed a possible use after free due to improper locking
 in ip_check_mc_rcu() (bsc#1200604).

CVE-2021-4157: Fixed an out of memory bounds write flaw in the NFS
 subsystem, related to the replication of files with NFS. A user could
 potentially crash the system or escalate privileges on the system
 (bsc#1194013).

CVE-2021-26341: Some AMD CPUs may transiently execute beyond
 unconditional direct branches, which may potentially result in data
 leakage (bsc#1201050).

CVE-2017-16525: Fixed a use-after-free after failed setup in
 usb/serial/console (bsc#1066618).

The following non-security bugs were fixed:

exec: Force single empty string when argv is empty (bsc#1200571).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.121~92.178.1", rls:"SLES12.0SP2"))) {
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
