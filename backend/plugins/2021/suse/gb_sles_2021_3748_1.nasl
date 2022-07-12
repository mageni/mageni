# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3748.1");
  script_cve_id("CVE-2018-13405", "CVE-2021-33033", "CVE-2021-34556", "CVE-2021-3542", "CVE-2021-35477", "CVE-2021-3655", "CVE-2021-3715", "CVE-2021-37159", "CVE-2021-3760", "CVE-2021-41864", "CVE-2021-42008", "CVE-2021-42252", "CVE-2021-42739");
  script_tag(name:"creation_date", value:"2021-11-21 03:21:15 +0000 (Sun, 21 Nov 2021)");
  script_version("2021-11-21T03:21:15+0000");
  script_tag(name:"last_modification", value:"2021-11-21 03:21:15 +0000 (Sun, 21 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-05 20:15:00 +0000 (Tue, 05 Jan 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3748-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3748-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213748-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:3748-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2021-3655: Fixed a missing size validations on inbound SCTP packets,
 which may have allowed the kernel to read uninitialized memory
 (bsc#1188563).

CVE-2021-3715: Fixed a use-after-free in route4_change() in
 net/sched/cls_route.c (bsc#1190349).

CVE-2021-33033: Fixed a use-after-free in cipso_v4_genopt in
 net/ipv4/cipso_ipv4.c because the CIPSO and CALIPSO refcounting for the
 DOI definitions is mishandled (bsc#1186109).

CVE-2021-3760: Fixed a use-after-free vulnerability with the
 ndev->rf_conn_info object (bsc#1190067).

CVE-2021-42739: The firewire subsystem had a buffer overflow related to
 drivers/media/firewire/firedtv-avc.c and
 drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt mishandled
 bounds checking (bsc#1184673).

CVE-2021-3542: Fixed heap buffer overflow in firedtv driver
 (bsc#1186063).

CVE-2021-34556: Fixed side-channel attack via a Speculative Store Bypass
 via unprivileged BPF program that could have obtain sensitive
 information from kernel memory (bsc#1188983).

CVE-2021-35477: Fixed BPF stack frame pointer which could have been
 abused to disclose content of arbitrary kernel memory (bsc#1188985).

CVE-2021-42252: Fixed an issue inside aspeed_lpc_ctrl_mmap that could
 have allowed local attackers to access the Aspeed LPC control interface
 to overwrite memory in the kernel and potentially execute privileges
 (bnc#1190479).

CVE-2021-41864: Fixed prealloc_elems_and_freelist that allowed
 unprivileged users to trigger an eBPF multiplication integer overflow
 with a resultant out-of-bounds write (bnc#1191317).

CVE-2021-42008: Fixed a slab out-of-bounds write in the decode_data
 function in drivers/net/hamradio/6pack.c. Input from a process that had
 the CAP_NET_ADMIN capability could have lead to root access
 (bsc#1191315).

CVE-2021-37159: Fixed use-after-free and a double free inside
 hso_free_net_device in drivers/net/usb/hso.c when unregister_netdev is
 called without checking for the NETREG_REGISTERED state (bnc#1188601).



The following non-security bugs were fixed:

IB/hfi1: Fix abba locking issue with sc_disable() (git-fixes)

KVM: PPC: Book3S HV: Save host FSCR in the P7/8 path (bsc#1065729).

NFS: Do uncached readdir when we're seeking a cookie in an empty page
 cache (bsc#1191628).

NFS: Fix backport error - dir_cookie is a pointer to a u64, not a u64.

PM: base: power: do not try to use non-existing RTC for storing data
 (git-fixes).

SMB3.1.1: Fix ids returned in POSIX query dir (bsc#1190317).

SMB3.1.1: do not log warning message if server does not populate salt
 (bsc#1190317).

SMB3.1.1: fix mount failure to some servers when compression enabled
 (bsc#1190317).

SMB3.1.1: remove confusing mount warning when no SPNEGO info on negprot
 rsp (bsc#1190317).

SMB3.1.1: update comments ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel-debuginfo", rpm:"kernel-default-devel-debuginfo~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~122.98.1", rls:"SLES12.0SP5"))) {
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
