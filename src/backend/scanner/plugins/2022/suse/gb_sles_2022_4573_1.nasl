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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.4573.1");
  script_cve_id("CVE-2021-4037", "CVE-2022-2153", "CVE-2022-28693", "CVE-2022-28748", "CVE-2022-2964", "CVE-2022-3169", "CVE-2022-33981", "CVE-2022-3424", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3542", "CVE-2022-3545", "CVE-2022-3565", "CVE-2022-3567", "CVE-2022-3586", "CVE-2022-3594", "CVE-2022-3621", "CVE-2022-3628", "CVE-2022-3629", "CVE-2022-3635", "CVE-2022-3643", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-3903", "CVE-2022-40307", "CVE-2022-40768", "CVE-2022-4095", "CVE-2022-41850", "CVE-2022-41858", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-42703", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-43750", "CVE-2022-4378", "CVE-2022-43945", "CVE-2022-45934");
  script_tag(name:"creation_date", value:"2022-12-20 04:18:02 +0000 (Tue, 20 Dec 2022)");
  script_version("2022-12-20T04:18:02+0000");
  script_tag(name:"last_modification", value:"2022-12-20 04:18:02 +0000 (Tue, 20 Dec 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 15:27:00 +0000 (Mon, 12 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:4573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:4573-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20224573-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:4573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2022-4378: Fixed stack overflow in __do_proc_dointvec (bsc#1206207).

CVE-2022-42328: Guests could trigger denial of service via the netback
 driver (bsc#1206114).

CVE-2022-42329: Guests could trigger denial of service via the netback
 driver (bsc#1206113).

CVE-2022-3643: Guests could trigger NIC interface reset/abort/crash via
 netback driver (bsc#1206113).

CVE-2022-3635: Fixed a use-after-free in the tst_timer() of the file
 drivers/atm/idt77252.c (bsc#1204631).

CVE-2022-41850: Fixed a race condition in roccat_report_event() in
 drivers/hid/hid-roccat.c (bsc#1203960).

CVE-2022-45934: Fixed a integer wraparound via L2CAP_CONF_REQ packets in
 l2cap_config_req in net/bluetooth/l2cap_core.c (bsc#1205796).

CVE-2022-3567: Fixed a to race condition in
 inet6_stream_ops()/inet6_dgram_ops() (bsc#1204414).

CVE-2022-41858: Fixed a denial of service in sl_tx_timeout() in
 drivers/net/slip (bsc#1205671).

CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation
 (bsc#1205128).

CVE-2022-4095: Fixed a use-after-free in rtl8712 driver (bsc#1205514).

CVE-2022-3903: Fixed a denial of service with the Infrared Transceiver
 USB driver (bsc#1205220).

CVE-2022-42896: Fixed a use-after-free vulnerability in the
 net/bluetooth/l2cap_core.c's l2cap_connect() and l2cap_le_connect_req()
 which may have allowed code execution and leaking kernel memory
 (respectively) remotely via Bluetooth (bsc#1205709).

CVE-2022-42895: Fixed an information leak in the
 net/bluetooth/l2cap_core.c's l2cap_parse_conf_req() which can be used to
 leak kernel pointers remotely (bsc#1205705).

CVE-2022-3424: Fixed use-after-free in gru_set_context_option(),
 gru_fault() and gru_handle_user_call_os() that could lead to kernel
 panic (bsc#1204166).

CVE-2022-3628: Fixed potential buffer overflow in
 brcmf_fweh_event_worker() in wifi/brcmfmac (bsc#1204868).

CVE-2022-2964: Fixed memory corruption issues in ax88179_178a devices
 (bsc#1202686).

CVE-2021-4037: Fixed function logic vulnerability that allowed local
 users to create files for the XFS file-system with an unintended group
 ownership and with group execution and SGID permission bits set
 (bsc#1198702).

CVE-2022-43750: Fixed vulnerability in usbmon that allowed a user-space
 client to corrupt the monitor's internal memory (bsc#1204653).

CVE-2022-3542: Fixed memory leak in bnx2x_tpa_stop() in
 drivers/net/ethernet/broadcom/bnx2x/bnx2x_cmn.c (bsc#1204402).

CVE-2022-3629: Fixed memory leak in vsock_connect() in
 net/vmw_vsock/af_vsock.c (bsc#1204635).

CVE-2022-3646: Fixed memory leak in nilfs_attach_log_writer() in
 fs/nilfs2/segment.c (bsc#1204646).

CVE-2022-3649: Fixed use-after-free in nilfs_new_inode() in
 fs/nilfs2/inode.c (bsc#1204647).

CVE-2022-3621: Fixed null pointer dereference in
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Availability 15, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Live Patching 15, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debuginfo", rpm:"kernel-zfcpdump-debuginfo~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-zfcpdump-debugsource", rpm:"kernel-zfcpdump-debugsource~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default-debuginfo", rpm:"reiserfs-kmp-default-debuginfo~4.12.14~150000.150.109.1", rls:"SLES15.0"))) {
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
