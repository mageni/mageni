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
  script_oid("1.3.6.1.4.1.25623.1.0.854965");
  script_version("2022-09-09T08:44:16+0000");
  script_cve_id("CVE-2021-3802");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-09-09 08:44:16 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-01 15:44:00 +0000 (Wed, 01 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-09-08 01:01:58 +0000 (Thu, 08 Sep 2022)");
  script_name("openSUSE: Security Advisory for udisks2 (SUSE-SU-2022:3154-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3154-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/I44C32TZ33CDLTTJ3MHFXQ6ANMP67MDZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'udisks2'
  package(s) announced via the SUSE-SU-2022:3154-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for udisks2 fixes the following issues:

  - CVE-2021-3802: Fixed insecure defaults in user-accessible mount helpers
       (bsc#1190606).

  - Fixed vulnerability that allowed mounting ext4 devices over existing
       entries in fstab (bsc#1098797).");

  script_tag(name:"affected", value:"'udisks2' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0", rpm:"libudisks2-0~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0-debuginfo", rpm:"libudisks2-0-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0-devel", rpm:"libudisks2-0-devel~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_bcache", rpm:"libudisks2-0_bcache~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_bcache-debuginfo", rpm:"libudisks2-0_bcache-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_btrfs", rpm:"libudisks2-0_btrfs~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_btrfs-debuginfo", rpm:"libudisks2-0_btrfs-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_lsm", rpm:"libudisks2-0_lsm~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_lsm-debuginfo", rpm:"libudisks2-0_lsm-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_lvm2", rpm:"libudisks2-0_lvm2~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_lvm2-debuginfo", rpm:"libudisks2-0_lvm2-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_zram", rpm:"libudisks2-0_zram~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudisks2-0_zram-debuginfo", rpm:"libudisks2-0_zram-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-UDisks-2_0", rpm:"typelib-1_0-UDisks-2_0~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2", rpm:"udisks2~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-debuginfo", rpm:"udisks2-debuginfo~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-debugsource", rpm:"udisks2-debugsource~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udisks2-lang", rpm:"udisks2-lang~2.8.1~150200.3.3.1", rls:"openSUSELeap15.3"))) {
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