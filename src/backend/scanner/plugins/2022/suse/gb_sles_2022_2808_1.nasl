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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2808.1");
  script_cve_id("CVE-2021-26341", "CVE-2021-33655", "CVE-2021-33656", "CVE-2022-1462");
  script_tag(name:"creation_date", value:"2022-08-16 04:41:23 +0000 (Tue, 16 Aug 2022)");
  script_version("2022-08-16T10:20:04+0000");
  script_tag(name:"last_modification", value:"2022-08-16 10:20:04 +0000 (Tue, 16 Aug 2022)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 13:44:00 +0000 (Thu, 28 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2808-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2808-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222808-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:2808-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-26341: Some AMD CPUs may transiently execute beyond
 unconditional direct branches, which may potentially result in data
 leakage (bsc#1201050).

CVE-2021-33655: Fixed out of bounds write with ioctl FBIOPUT_VSCREENINFO
 (bnc#1201635).

CVE-2021-33656: Fixed out of bounds write with ioctl PIO_FONT
 (bnc#1201636).

CVE-2022-1462: Fixed an out-of-bounds read flaw in the TeleTYpe
 subsystem (bnc#1198829).

The following non-security bugs were fixed:

Add missing recommends of kernel-install-tools to kernel-source-vanilla
 (bsc#1200442)

cifs: On cifs_reconnect, resolve the hostname again (bsc#1201926).

cifs: Simplify reconnect code when dfs upcall is enabled (bsc#1201926).

cifs: To match file servers, make sure the server hostname matches
 (bsc#1201926).

cifs: fix memory leak of smb3_fs_context_dup::server_hostname
 (bsc#1201926).

cifs: fix potential use-after-free in cifs_echo_request() (bsc#1201926).

cifs: set a minimum of 120s for next dns resolution (bsc#1201926).

cifs: use the expiry output of dns_query to schedule next resolution
 (bsc#1201926).

kernel-binary.spec: Support radio selection for debuginfo. To disable
 debuginfo on 5.18 kernel a radio selection needs to be switched to a
 different selection. This requires disabling the currently active option
 and selecting NONE as debuginfo type.

kvm: emulate: Fix SETcc emulation function offsets with SLS
 (bsc#1201930).

kvm: emulate: do not adjust size of fastop and setcc subroutines
 (bsc#1201930).

pahole 1.22 required for full BTF features. also recommend pahole for
 kernel-source to make the kernel buildable with standard config

rpm/*.spec.in: remove backtick usage

rpm/constraints.in: skip SLOW_DISK workers for kernel-source

rpm/kernel-obs-build.spec.in: Also depend on dracut-systemd (bsc#1195775)

rpm/kernel-obs-build.spec.in: add systemd-initrd and terminfo dracut
 module (bsc#1195775)

rpm/kernel-obs-build.spec.in: use default dracut modules (bsc#1195926,
 bsc#1198484).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP4, SUSE Linux Enterprise Live Patching 12-SP4, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.105.1", rls:"SLES12.0SP4"))) {
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
