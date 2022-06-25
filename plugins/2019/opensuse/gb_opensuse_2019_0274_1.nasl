# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852327");
  script_version("2019-04-16T07:10:04+0000");
  script_cve_id("CVE-2018-5391", "CVE-2019-3459", "CVE-2019-3460", "CVE-2019-7221", "CVE-2019-7222");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-04-16 07:10:04 +0000 (Tue, 16 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-02 04:07:53 +0100 (Sat, 02 Mar 2019)");
  script_name("SuSE Update for the openSUSE-SU-2019:0274-1 (the)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00000.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the'
  package(s) announced via the openSUSE-SU-2019:0274_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The openSUSE Leap 42.3 kernel was updated to 4.4.175 to receive various
  bugfixes.

  The following security bugs were fixed:

  - CVE-2018-5391: Fixed a vulnerability, which allowed an attacker to cause
  a denial of service attack with low rates of packets targeting IP
  fragment re-assembly. (bsc#1103097)

  - CVE-2019-7221: Fixed a user-after-free vulnerability in the KVM
  hypervisor related to the emulation of a preemption timer, allowing an
  guest user/process to crash the host kernel. (bsc#1124732).

  - CVE-2019-7222: Fixed an information leakage in the KVM hypervisor
  related to handling page fault exceptions, which allowed a guest
  user/process to use this flaw to leak the host's stack memory contents
  to a guest (bsc#1124735).

  The following non-security bugs were fixed:

  - ASoC: Intel: mrfld: fix uninitialized variable access (bnc#1012382).

  - ASoC: atom: fix a missing check of snd_pcm_lib_malloc_pages
  (bnc#1012382).

  - ASoC: fsl: Fix SND_SOC_EUKREA_TLV320 build error on i.MX8M (bnc#1012382).

  - Documentation/network: reword kernel version reference (bnc#1012382).

  - IB/core: type promotion bug in rdma_rw_init_one_mr() ().

  - IB/rxe: Fix incorrect cache cleanup in error flow ().

  - IB/rxe: replace kvfree with vfree ().

  - NFC: nxp-nci: Include unaligned.h instead of access_ok.h (bnc#1012382).

  - RDMA/bnxt_re: Fix a couple off by one bugs (bsc#1020413, ).

  - RDMA/bnxt_re: Synchronize destroy_qp with poll_cq (bsc#1125446).

  - Revert 'Input: elan_i2c - add ACPI ID for touchpad in ASUS Aspire
  F5-573G' (bnc#1012382).

  - Revert 'cifs: In Kconfig CONFIG_CIFS_POSIX needs depends on legacy
  (insecure cifs)' (bnc#1012382).

  - Revert 'exec: load_script: do not blindly truncate shebang string'
  (bnc#1012382).

  - Revert 'loop: Fix double mutex_unlock(&amp loop_ctl_mutex) in
  loop_control_ioctl()' (bnc#1012382).

  - Revert 'loop: Fold __loop_release into loop_release' (bnc#1012382).

  - Revert 'loop: Get rid of loop_index_mutex' (bnc#1012382).

  - Revert 'mmc: bcm2835: Fix DMA channel leak on probe error (bsc#1120902).'

  - Revert most of 4.4.174 (kabi).

  - acpi, nfit: Fix ARS overflow continuation (bsc#1125000).

  - acpi/nfit: fix cmd_rc for acpi_nfit_ctl to always return a value
  (bsc#1124775).

  - alpha: Fix Eiger NR_IRQS to 128 (bnc#1012382).

  - alpha: fix page fault handling for r16-r18 targets (bnc#1012382).

  - alsa: compress: Fix stop handling on compressed capture streams
  (bnc#1012382).

  - alsa: hda - Add quirk for HP EliteBook 840 G5 (bnc#1012382).

  - alsa: hda - Serialize codec registrations (bnc#1012382).

  - alsa: usb-audio: Fix implicit fb e ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"the on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs-pdf", rpm:"kernel-docs-pdf~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.4.175~89.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
