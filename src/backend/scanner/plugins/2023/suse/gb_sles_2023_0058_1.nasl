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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0058.1");
  script_cve_id("CVE-2022-4415");
  script_tag(name:"creation_date", value:"2023-01-11 04:19:15 +0000 (Wed, 11 Jan 2023)");
  script_version("2023-01-23T10:11:56+0000");
  script_tag(name:"last_modification", value:"2023-01-23 10:11:56 +0000 (Mon, 23 Jan 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-19 18:07:00 +0000 (Thu, 19 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0058-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0058-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230058-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd' package(s) announced via the SUSE-SU-2023:0058-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for systemd fixes the following issues:

Fixing the following issues:

units: restore RemainAfterExit=yes in systemd-vconsole-setup.service

vconsole-setup: don't concat strv if we don't need to (i.e. not in debug
 log mode)

vconsole-setup: add more log messages

units: restore Before dependencies for systemd-vconsole-setup.service

vconsole-setup: add lots of debug messages

Add enable_disable() helper

vconsole: correct kernel command line namespace

vconsole: Don't do static installation under sysinit.target

vconsole: use KD_FONT_OP_GET/SET to handle copying (bsc#1181636)

vconsole: updates of keyboard/font loading functions

vconsole: Add generic is_*() functions

vconsole: add two new toggle functions, remove old enable/disable ones

vconsole: copy font to 63 consoles instead of 15

vconsole: add log_oom() where appropriate

vconsole-setup: Store fonts on heap (#3268)

errno-util: add new errno_or_else() helper

The following fix is now integrated upstream:

CVE-2022-4415: coredump: do not allow user to access coredumps with
 changed uid/gid/capabilities (bsc#1205000).");

  script_tag(name:"affected", value:"'systemd' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0", rpm:"libsystemd0~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-32bit", rpm:"libsystemd0-32bit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo", rpm:"libsystemd0-debuginfo~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsystemd0-debuginfo-32bit", rpm:"libsystemd0-debuginfo-32bit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev-devel", rpm:"libudev-devel~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1", rpm:"libudev1~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-32bit", rpm:"libudev1-32bit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo", rpm:"libudev1-debuginfo~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libudev1-debuginfo-32bit", rpm:"libudev1-debuginfo-32bit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-32bit", rpm:"systemd-32bit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-bash-completion", rpm:"systemd-bash-completion~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo", rpm:"systemd-debuginfo~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debuginfo-32bit", rpm:"systemd-debuginfo-32bit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-debugsource", rpm:"systemd-debugsource~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-devel", rpm:"systemd-devel~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"systemd-sysvinit", rpm:"systemd-sysvinit~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev", rpm:"udev~228~157.49.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"udev-debuginfo", rpm:"udev-debuginfo~228~157.49.1", rls:"SLES12.0SP5"))) {
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
