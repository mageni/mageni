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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1676.1");
  script_cve_id("CVE-2020-27835", "CVE-2021-0707", "CVE-2021-20292", "CVE-2021-20321", "CVE-2021-38208", "CVE-2021-4154", "CVE-2022-0812", "CVE-2022-1158", "CVE-2022-1280", "CVE-2022-1353", "CVE-2022-1419", "CVE-2022-1516", "CVE-2022-28356", "CVE-2022-28748", "CVE-2022-28893", "CVE-2022-29156");
  script_tag(name:"creation_date", value:"2022-05-17 04:28:29 +0000 (Tue, 17 May 2022)");
  script_version("2022-05-17T11:51:58+0000");
  script_tag(name:"last_modification", value:"2022-05-19 09:49:33 +0000 (Thu, 19 May 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-20 16:26:00 +0000 (Wed, 20 Apr 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1676-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1676-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221676-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2022:1676-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security and bugfixes.


The following security bugs were fixed:

CVE-2020-27835: Fixed a use after free vulnerability in infiniband hfi1
 driver in the way user calls Ioctl after open dev file and fork. A local
 user could use this flaw to crash the system (bnc#1179878).

CVE-2021-0707: Fixed a use after free vulnerability in dma_buf_release
 of dma-buf.c, which may lead to local escalation of privilege with no
 additional execution privileges needed (bnc#1198437).

CVE-2021-20292: Fixed object validation prior to performing operations
 on the object in nouveau_sgdma_create_ttm in Nouveau DRM subsystem
 (bnc#1183723).

CVE-2021-20321: Fixed a race condition accessing file object in the
 OverlayFS subsystem in the way users do rename in specific way with
 OverlayFS. A local user could have used this flaw to crash the system
 (bnc#1191647).

CVE-2021-38208: Fixed a denial of service (NULL pointer dereference and
 BUG) by making a getsockname call after a certain type of failure of a
 bind call (bnc#1187055).

CVE-2021-4154: Fixed a use-after-free vulnerability in
 cgroup1_parse_param in kernel/cgroup/cgroup-v1.c, allowing a local
 privilege escalation by an attacker with user privileges by exploiting
 the fsconfig syscall parameter, leading to a container breakout and a
 denial of service on the system (bnc#1193842).

CVE-2022-0812: Fixed information leak when a file is read from RDMA
 (bsc#1196639)

CVE-2022-1158: Fixed a vulnerability in the kvm module that may lead to
 a use-after-free write or denial of service (bsc#1197660).

CVE-2022-1280: Fixed a use-after-free vulnerability in drm_lease_held in
 drivers/gpu/drm/drm_lease.c (bnc#1197914).

CVE-2022-1353: Fixed access control to kernel memory in the
 pfkey_register function in net/key/af_key.c (bnc#1198516).

CVE-2022-1419: Fixed a concurrency use-after-free in
 vgem_gem_dumb_create (bsc#1198742).

CVE-2022-1516: Fixed null-ptr-deref caused by x25_disconnect
 (bsc#1199012).

CVE-2022-28356: Fixed a refcount leak bug in net/llc/af_llc.c
 (bnc#1197391).

CVE-2022-28748: Fixed memory lead over the network by ax88179_178a
 devices (bsc#1196018).

CVE-2022-28893: Fixed a use after free vulnerability in inet_put_port
 where some sockets are not closed before xs_xprt_free() (bsc#1198330).

CVE-2022-29156: Fixed a double free vulnerability related to
 rtrs_clt_dev_release.ate (jsc#SLE-15176 bsc#1198515).

The following non-security bugs were fixed:

ACPI/APEI: Limit printable size of BERT table data (git-fixes).

ACPI: processor idle: Check for architectural support for LPI
 (git-fixes).

ACPICA: Avoid walking the ACPI Namespace if it is not there (git-fixes).

ALSA: cs4236: fix an incorrect NULL check on list iterator (git-fixes).

ALSA: hda/hdmi: fix warning about PCM count when used with SOF
 (git-fixes).

ALSA: hda/realtek: Add ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debugsource", rpm:"kernel-azure-debugsource~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel-debuginfo", rpm:"kernel-azure-devel-debuginfo~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~5.3.18~150300.38.56.1", rls:"SLES15.0SP3"))) {
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
