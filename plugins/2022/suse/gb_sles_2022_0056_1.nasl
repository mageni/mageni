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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0056.1");
  script_cve_id("CVE-2020-24504", "CVE-2020-27820", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28714", "CVE-2021-28715", "CVE-2021-33098", "CVE-2021-4001", "CVE-2021-4002", "CVE-2021-43975", "CVE-2021-43976", "CVE-2021-45485", "CVE-2021-45486");
  script_tag(name:"creation_date", value:"2022-01-12 03:23:38 +0000 (Wed, 12 Jan 2022)");
  script_version("2022-01-12T03:23:38+0000");
  script_tag(name:"last_modification", value:"2022-01-12 11:02:51 +0000 (Wed, 12 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-29 19:38:00 +0000 (Mon, 29 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0056-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0056-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220056-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:0056-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated.

The following security bugs were fixed:

CVE-2021-45485: Fixed an information leak because of certain use of a
 hash table which use IPv6 source addresses. (bsc#1194094)

CVE-2021-45486: Fixed an information leak because the hash table is very
 small in net/ipv4/route.c. (bnc#1194087).

CVE-2021-4001: Fixed a race condition when the EBPF map is frozen.
 (bsc#1192990)

CVE-2021-28715: Fixed an issue where a guest could force Linux netback
 driver to hog large amounts of kernel memory by do not queueing
 unlimited number of packages. (bsc#1193442)

CVE-2021-28714: Fixed an issue where a guest could force Linux netback
 driver to hog large amounts of kernel memory by fixing rx queue stall
 detection. (bsc#1193442)

CVE-2021-28713: Fixed a rogue backends that could cause DoS of guests
 via high frequency events by hardening hvc_xen against event channel
 storms. (bsc#1193440)

CVE-2021-28712: Fixed a rogue backends that could cause DoS of guests
 via high frequency events by hardening netfront against event channel
 storms. (bsc#1193440)

CVE-2021-28711: Fixed a rogue backends that could cause DoS of guests
 via high frequency events by hardening blkfront against event channel
 storms. (bsc#1193440)

CVE-2020-24504: Fixed an uncontrolled resource consumption in some
 Intel(R) Ethernet E810 Adapter drivers that may have allowed an
 authenticated user to potentially enable denial of service via local
 access. (bnc#1182404)

CVE-2021-43975: Fixed a flaw in hw_atl_utils_fw_rpc_wait that could
 allow an attacker (who can introduce a crafted device) to trigger an
 out-of-bounds write via a crafted length value. (bnc#1192845)

CVE-2021-43976: Fixed a flaw that could allow an attacker (who can
 connect a crafted USB device) to cause a denial of service. (bnc#1192847)

CVE-2021-4002: Added a missing TLB flush that could lead to leak or
 corruption of data in hugetlbfs. (bsc#1192946)

CVE-2020-27820: Fixed a vulnerability where a use-after-frees in
 nouveau's postclose() handler could happen if removing device.
 (bnc#1179599)

CVE-2021-33098: Fixed a potential denial of service in Intel(R) Ethernet
 ixgbe driver due to improper input validation. (bnc#1192877)

The following non-security bugs were fixed:

ACPI: battery: Accept charges over the design capacity as full
 (git-fixes).

ACPI: PMIC: Fix intel_pmic_regs_handler() read accesses (git-fixes).

ACPICA: Avoid evaluating methods too early during system resume
 (git-fixes).

ALSA: ctxfi: Fix out-of-range access (git-fixes).

ALSA: gus: fix null pointer dereference on pointer block (git-fixes).

ALSA: hda: hdac_ext_stream: fix potential locking issues (git-fixes).

ALSA: hda: hdac_stream: fix potential locking issue in
 snd_hdac_stream_assign() (git-fixes).

ALSA: hda/realtek: Add a quirk for Acer Spin SP513-54N (git-fixes).

ALSA: hda/realtek: Add quirk for ASUS UX550VE ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~38.34.1", rls:"SLES15.0SP3"))) {
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
