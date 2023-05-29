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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2162.1");
  script_cve_id("CVE-2020-36691", "CVE-2022-43945", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1855", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-2124", "CVE-2023-2162", "CVE-2023-2483", "CVE-2023-30772");
  script_tag(name:"creation_date", value:"2023-05-11 04:20:58 +0000 (Thu, 11 May 2023)");
  script_version("2023-05-11T09:09:33+0000");
  script_tag(name:"last_modification", value:"2023-05-11 09:09:33 +0000 (Thu, 11 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 14:30:00 +0000 (Fri, 07 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2162-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2162-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232162-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:2162-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP5 AZURE kernel was updated to receive various security and bugfixes.
The following security bugs were fixed:

CVE-2023-2483: Fixed a use after free bug in emac_remove due caused by a race condition (bsc#1211037).
CVE-2023-2124: Fixed an out of bound access in the XFS subsystem that could have lead to denial-of-service or potentially privilege escalation (bsc#1210498).
CVE-2023-1670: Fixed a use after free in the Xircom 16-bit PCMCIA Ethernet driver. A local user could use this flaw to crash the system or potentially escalate their privileges on the system (bsc#1209871).
CVE-2023-2162: Fixed an use-after-free flaw in iscsi_sw_tcp_session_create (bsc#1210647).
CVE-2023-1998: Fixed a use after free during login when accessing the shost ipaddress (bsc#1210506).
CVE-2023-30772: Fixed a race condition and resultant use-after-free in da9150_charger_remove (bsc#1210329).
CVE-2023-1855: Fixed a use after free in xgene_hwmon_remove (bsc#1210202).
CVE-2023-1989: Fixed a use after free in btsdio_remove (bsc#1210336).
CVE-2023-1990: Fixed a use after free in ndlc_remove (bsc#1210337).
CVE-2022-43945: Fixed a buffer overflow in the NFSD implementation (bsc#1205128).
CVE-2023-1611: Fixed an use-after-free flaw in btrfs_search_slot (bsc#1209687).
CVE-2020-36691: Fixed a denial of service vulnerability via a nested Netlink policy with a back reference (bsc#1209777).

The following non-security bugs were fixed:

USB: dwc3: fix runtime pm imbalance on probe errors (git-fixes).
USB: dwc3: fix runtime pm imbalance on unbind (git-fixes).
ath10k: Fix error handling in case of CE pipe init failure (git-fixes).
ath10k: Fix missing frame timestamp for beacon/probe-resp (git-fixes).
ath10k: Fix the parsing error in service available event (git-fixes).
ath10k: add missing error return code in ath10k_pci_probe() (git-fixes).
ath10k: fix control-message timeout (git-fixes).
ath10k: fix division by zero in send path (git-fixes).
ath10k: fix memory overwrite of the WoWLAN wakeup packet pattern (git-fixes).
audit: improve audit queue handling when 'audit=1' on cmdline (bsc#1209969).
bpf, x86: Fix encoding for lower 8-bit registers in BPF_STX BPF_B (git-fixes).
cachefiles: Drop superfluous readpages aops NULL check (bsc#1210430).
cachefiles: Fix page leak in cachefiles_read_backing_file while vmscan is active (bsc#1210430).
cachefiles: Fix race between read_waiter and read_copier involving op->to_do (bsc#1210430).
cachefiles: Handle readpage error correctly (bsc#1210430).
cgroup/cpuset: Wake up cpuset_attach_wq tasks in cpuset_cancel_attach() (bsc#1210827).
cifs: fix negotiate context parsing (bsc#1210301).
cifs: fix open leaks in open_cached_dir() (bsc#1209342).
cred: allow get_cred() and put_cred() to be given NULL (bsc#1209887).
crypto: x86/ghash - fix unaligned access in ghash_setkey() (git-fixes).
drivers: net: lmc: fix case value for target abort error ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~16.133.1", rls:"SLES12.0SP5"))) {
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
