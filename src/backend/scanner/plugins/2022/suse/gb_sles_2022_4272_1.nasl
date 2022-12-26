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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4272.1");
  script_cve_id("CVE-2021-4037", "CVE-2022-2153", "CVE-2022-2964", "CVE-2022-3169", "CVE-2022-3424", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-3629", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-40307", "CVE-2022-40768", "CVE-2022-42703", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2022-11-30 04:20:10 +0000 (Wed, 30 Nov 2022)");
  script_version("2022-11-30T10:12:07+0000");
  script_tag(name:"last_modification", value:"2022-11-30 10:12:07 +0000 (Wed, 30 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 14:45:00 +0000 (Tue, 25 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4272-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4272-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224272-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4272-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-4037: Fixed function logic vulnerability that allowed local
 users to create files for the XFS file-system with an unintended group
 ownership and with group execution and SGID permission bits set
 (bnc#1198702).

CVE-2022-2153: Fixed vulnerability in KVM that could allow an
 unprivileged local attacker on the host to cause DoS (bnc#1200788).

CVE-2022-2964: Fixed memory corruption issues in ax88179_178a devices
 (bnc#1202686).

CVE-2022-3169: Fixed a denial of service flaw which occurs when
 consecutive requests to NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET
 are sent (bnc#1203290).

CVE-2022-3521: Fixed race condition in kcm_tx_work() in
 net/kcm/kcmsock.c (bnc#1204355).

CVE-2022-3524: Fixed memory leak in ipv6_renew_options() in the IPv6
 handler (bnc#1204354).

CVE-2022-3542: Fixed memory leak in bnx2x_tpa_stop() in
 drivers/net/ethernet/broadcom/bnx2x/bnx2x_cmn.c (bnc#1204402).

CVE-2022-3545: Fixed use-after-free in area_cache_get() in
 drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c (bnc#1204415).

CVE-2022-3565: Fixed use-after-free in del_timer() in
 drivers/isdn/mISDN/l1oip_core.c (bnc#1204431).

CVE-2022-3586: Fixed use-after-free in socket buffer (SKB) that could
 allow a local unprivileged user to cause a denial of service
 (bnc#1204439).

CVE-2022-3594: Fixed excessive data logging in intr_callback() in
 drivers/net/usb/r8152.c (bnc#1204479).

CVE-2022-3621: Fixed null pointer dereference in
 nilfs_bmap_lookup_at_level() in fs/nilfs2/inode.c (bnc#1204574).

CVE-2022-3629: Fixed memory leak in vsock_connect() in
 net/vmw_vsock/af_vsock.c (bnc#1204635).

CVE-2022-3646: Fixed memory leak in nilfs_attach_log_writer() in
 fs/nilfs2/segment.c (bnc#1204646).

CVE-2022-3649: Fixed use-after-free in nilfs_new_inode() in
 fs/nilfs2/inode.c (bnc#1204647).

CVE-2022-40307: Fixed a race condition that could had been exploited to
 trigger a use-after-free in the efi firmware capsule-loader.c
 (bnc#1203322).

CVE-2022-40768: Fixed information leak in the scsi driver which allowed
 local users to obtain sensitive information from kernel memory
 (bnc#1203514).

CVE-2022-42703: Fixed use-after-free in mm/rmap.c related to leaf
 anon_vma double reuse (bnc#1204168).

CVE-2022-43750: Fixed vulnerability in usbmon that allowed a user-space
 client to corrupt the monitor's internal memory (bnc#1204653).

The following non-security bugs were fixed:

ACPI: processor idle: Practically limit 'Dummy wait' workaround to old
 Intel systems (bnc#1203802).

ACPI: processor_idle: Skip dummy wait if kernel is in guest
 (bnc#1203802).

Input: gscps2 - check return value of ioremap() in gscps2_probe()
 (git-fixes).

Input: xpad - add supported devices as contributed on github (git-fixes).

KVM: x86/emulator: Fix handing of POP SS to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 12-SP5, SUSE Linux Enterprise Live Patching 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.139.1", rls:"SLES12.0SP5"))) {
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
