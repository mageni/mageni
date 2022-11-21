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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4072.1");
  script_cve_id("CVE-2022-1882", "CVE-2022-2153", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-2978", "CVE-2022-3169", "CVE-2022-33981", "CVE-2022-3424", "CVE-2022-3435", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3526", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3577", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3619", "CVE-2022-3621", "CVE-2022-3625", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-3633", "CVE-2022-3640", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-40476", "CVE-2022-40768", "CVE-2022-42703", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2022-11-21 04:25:19 +0000 (Mon, 21 Nov 2022)");
  script_version("2022-11-21T04:25:19+0000");
  script_tag(name:"last_modification", value:"2022-11-21 04:25:19 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 14:45:00 +0000 (Tue, 25 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4072-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4072-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224072-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4072-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2022-28748: Fixed a leak of kernel memory over the network by
 ax88179_178a devices (bsc#1196018).

CVE-2022-1882: Fixed a use-after-free flaw in free_pipe_info() that
 could allow a local user to crash or potentially escalate their
 privileges on the system (bsc#1199904).

CVE-2022-2964: Fixed memory corruption issues in ax88179_178a devices
 (bnc#1202686).

CVE-2022-3169: Fixed an denial of service though request to
 NVME_IOCTL_RESET and NVME_IOCTL_SUBSYS_RESET (bsc#1203290).

CVE-2022-33981: Fixed a use-after-free in floppy driver (bnc#1200692).

CVE-2022-3424: Fixed use-after-free in gru_set_context_option(),
 gru_fault() and gru_handle_user_call_os() that could lead to kernel
 panic (bsc#1204166).

CVE-2022-3435: Fixed an out-of-bounds read in fib_nh_match() of the file
 net/ipv4/fib_semantics.c (bsc#1204171).

CVE-2022-3521: Fixed race condition in kcm_tx_work() in
 net/kcm/kcmsock.c (bnc#1204355).

CVE-2022-3524: Fixed memory leak in ipv6_renew_options() in the IPv6
 handler (bnc#1204354).

CVE-2022-3526: Fixed a memory leak in macvlan_handle_frame() from
 drivers/net/macvlan.c (bnc#1204353).

CVE-2022-3545: Fixed use-after-free in area_cache_get() in
 drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c (bnc#1204415).

CVE-2022-3565: Fixed use-after-free in del_timer() in
 drivers/isdn/mISDN/l1oip_core.c (bnc#1204431).

CVE-2022-3621: Fixed null pointer dereference in
 nilfs_bmap_lookup_at_level() in fs/nilfs2/inode.c (bnc#1204574).

CVE-2022-3625: Fixed use-after-free in
 devlink_param_set()/devlink_param_get() in net/core/devlink.c
 (bnc#1204637).

CVE-2022-3628: Fixed potential buffer overflow in
 brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).

CVE-2022-3640: Fixed use-after-free in l2cap_conn_del() in
 net/bluetooth/l2cap_core.c (bnc#1204619).

CVE-2022-3646: Fixed memory leak in nilfs_attach_log_writer() in
 fs/nilfs2/segment.c (bnc#1204646).

CVE-2022-40476: Fixed a null pointer dereference in fs/io_uring.c
 (bnc#1203435).

CVE-2022-40768: Fixed information disclosure in stex_queuecommand_lck
 (bnc#1203514).

CVE-2022-43750: Fixed vulnerability in usbmon that allowed a user-space
 client to corrupt the monitor's internal memory (bnc#1204653).

The following non-security bugs were fixed:

acpi: APEI: do not add task_work to kernel thread to avoid memory leak
 (git-fixes).

acpi: HMAT: Release platform device in case of
 platform_device_add_data() fails (git-fixes).

acpi: extlog: Handle multiple records (git-fixes).

acpi: tables: FPDT: Do not call acpi_os_map_memory() on invalid phys
 address (git-fixes).

acpi: video: Add Toshiba Satellite/Portege Z830 quirk (git-fixes).

acpi: video: Make backlight class device registration a separate step
 (v2) (git-fixes).

acpi: x86: Add a quirk for Dell Inspiron 14 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15-SP4, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP4, SUSE Linux Enterprise Module for Development Tools 15-SP4, SUSE Linux Enterprise Module for Legacy Software 15-SP4, SUSE Linux Enterprise Module for Live Patching 15-SP4, SUSE Linux Enterprise Workstation Extension 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb", rpm:"kernel-64kb~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debuginfo", rpm:"kernel-64kb-debuginfo~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-debugsource", rpm:"kernel-64kb-debugsource~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel", rpm:"kernel-64kb-devel~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-64kb-devel-debuginfo", rpm:"kernel-64kb-devel-debuginfo~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.14.21~150400.24.33.2.150400.24.11.4", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.14.21~150400.24.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.14.21~150400.24.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump", rpm:"kernel-zfcpdump~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.14.21~150400.24.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~5.14.21~150400.24.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.14.21~150400.24.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.14.21~150400.24.33.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~5.14.21~150400.24.33.2", rls:"SLES15.0SP4"))) {
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
