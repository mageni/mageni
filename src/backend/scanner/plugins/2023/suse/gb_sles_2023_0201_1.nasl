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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0201.1");
  script_cve_id("CVE-2022-4415");
  script_tag(name:"creation_date", value:"2023-01-30 04:19:32 +0000 (Mon, 30 Jan 2023)");
  script_version("2023-01-30T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 18:07:00 +0000 (Thu, 19 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0201-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0201-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230201-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2023:0201-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

CVE-2022-4415: Fixed an issue where users could access coredumps with
 changed uid, gid or capabilities (bsc#1205000).

Non-security fixes:

Enabled the pstore service (jsc#PED-2663).

Fixed an issue accessing TPM when secure boot is enabled (bsc#1204944).

Fixed an issue where a pamd file could get accidentally overwritten
 after an update (bsc#1207264).");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit-debuginfo", rpm:"libsystemd0-32bit-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit-debuginfo", rpm:"libudev1-32bit-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit-debuginfo", rpm:"systemd-32bit-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container", rpm:"systemd-container~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-container-debuginfo", rpm:"systemd-container-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump", rpm:"systemd-coredump~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-coredump-debuginfo", rpm:"systemd-coredump-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-doc", rpm:"systemd-doc~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-lang", rpm:"systemd-lang~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~249.14~150400.8.19.1", rls:"SLES15.0SP4"))) {
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
