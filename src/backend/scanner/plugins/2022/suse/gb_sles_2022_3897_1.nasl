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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3897.1");
  script_cve_id("CVE-2021-4037", "CVE-2022-2153", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-2978", "CVE-2022-3169", "CVE-2022-3176", "CVE-2022-3424", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3535", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3577", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-3623", "CVE-2022-3625", "CVE-2022-3629", "CVE-2022-3640", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-39189", "CVE-2022-40768", "CVE-2022-41674", "CVE-2022-42703", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722", "CVE-2022-43750");
  script_tag(name:"creation_date", value:"2022-11-09 04:35:19 +0000 (Wed, 09 Nov 2022)");
  script_version("2022-11-09T04:35:19+0000");
  script_tag(name:"last_modification", value:"2022-11-09 04:35:19 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-25 14:45:00 +0000 (Tue, 25 Oct 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3897-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3897-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223897-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:3897-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

CVE-2021-4037: Fixed function logic vulnerability that allowed local
 users to create files for the XFS file-system with an unintended group
 ownership and with group execution and SGID permission bits set
 (bnc#1198702).

CVE-2022-2153: Fixed vulnerability in KVM that could allow an
 unprivileged local attacker on the host to cause DoS (bnc#1200788).

CVE-2022-2964, CVE-2022-28748: Fixed memory corruption issues in
 ax88179_178a devices (bnc#1202686 bsc#1196018).

CVE-2022-2978: Fixed use-after-free in the NILFS file system that could
 lead to local privilege escalation or DoS (bnc#1202700).

CVE-2022-3169: Fixed a denial of service flaw which occurs when
 consecutive requests to NVME_IOCTL_RESET and the NVME_IOCTL_SUBSYS_RESET
 are sent (bnc#1203290).

CVE-2022-3176: Fixed use-after-free in io_uring when using POLLFREE
 (bnc#1203391).

CVE-2022-3424: Fixed use-after-free in gru_set_context_option(),
 gru_fault() and gru_handle_user_call_os() that could lead to kernel
 panic (bsc#1204166).

CVE-2022-3521: Fixed race condition in kcm_tx_work() in
 net/kcm/kcmsock.c (bnc#1204355).

CVE-2022-3524: Fixed memory leak in ipv6_renew_options() in the IPv6
 handler (bnc#1204354).

CVE-2022-3535: Fixed memory leak in mvpp2_dbgfs_port_init() in
 drivers/net/ethernet/marvell/mvpp2/mvpp2_debugfs.c (bnc#1204417).

CVE-2022-3542: Fixed memory leak in bnx2x_tpa_stop() in
 drivers/net/ethernet/broadcom/bnx2x/bnx2x_cmn.c (bnc#1204402).

CVE-2022-3545: Fixed use-after-free in area_cache_get() in
 drivers/net/ethernet/netronome/nfp/nfpcore/nfp_cppcore.c (bnc#1204415).

CVE-2022-3565: Fixed use-after-free in del_timer() in
 drivers/isdn/mISDN/l1oip_core.c (bnc#1204431).

CVE-2022-3577: Fixed out-of-bounds memory write flaw in bigben device
 driver that could lead to local privilege escalation or DoS
 (bnc#1204470).

CVE-2022-3586: Fixed use-after-free in socket buffer (SKB) that could
 allow a local unprivileged user to cause a denial of service
 (bnc#1204439).

CVE-2022-3594: Fixed excessive data logging in intr_callback() in
 drivers/net/usb/r8152.c (bnc#1204479).

CVE-2022-3621: Fixed null pointer dereference in
 nilfs_bmap_lookup_at_level() in fs/nilfs2/inode.c (bnc#1204574).

CVE-2022-3623: Fixed race condition in follow_page_pte() (mm/gup.c)
 (bsc#1204575).

CVE-2022-3625: Fixed use-after-free in
 devlink_param_set()/devlink_param_get() in net/core/devlink.c
 (bnc#1204637).

CVE-2022-3629: Fixed memory leak in vsock_connect() in
 net/vmw_vsock/af_vsock.c (bnc#1204635).

CVE-2022-3640: Fixed use-after-free in l2cap_conn_del() in
 net/bluetooth/l2cap_core.c (bnc#1204619).

CVE-2022-3646: Fixed memory leak in nilfs_attach_log_writer() in
 fs/nilfs2/segment.c (bnc#1204646).

CVE-2022-3649: Fixed use-after-free in nilfs_new_inode() in
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.83.1", rls:"SLES15.0SP3"))) {
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
