###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2495_1.nasl 13943 2019-02-28 15:28:52Z cfischer $
#
# SuSE Update for the Linux Kernel openSUSE-SU-2017:2495-1 (kernel)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851618");
  script_version("$Revision: 13943 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 16:28:52 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2017-09-16 07:27:49 +0200 (Sat, 16 Sep 2017)");
  script_cve_id("CVE-2017-1000251", "CVE-2017-11472", "CVE-2017-12134", "CVE-2017-14051",
                "CVE-2017-14106");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for the Linux Kernel openSUSE-SU-2017:2495-1 (kernel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The openSUSE Leap 42.2 kernel was updated
  to 4.4.87 to receive various security and bugfixes.


  The following security bugs were fixed:

  - CVE-2017-1000251: The native Bluetooth stack in the Linux Kernel (BlueZ)
  was vulnerable to a stack overflow vulnerability in the processing of
  L2CAP configuration responses resulting in Remote code execution in
  kernel space (bnc#1057389).

  - CVE-2017-14106: The tcp_disconnect function in net/ipv4/tcp.c in the
  Linux kernel allowed local users to cause a denial of service
  (__tcp_select_window divide-by-zero error and system crash) by
  triggering a disconnect within a certain tcp_recvmsg code path
  (bnc#1056982).

  - CVE-2017-11472: The acpi_ns_terminate() function in
  drivers/acpi/acpica/nsutils.c in the Linux kernel did not flush the
  operand cache and causes a kernel stack dump, which allowed local users
  to obtain sensitive information from kernel memory and bypass the KASLR
  protection mechanism (in the kernel through 4.9) via a crafted ACPI
  table (bnc#1049580).

  - CVE-2017-14051: An integer overflow in the
  qla2x00_sysfs_write_optrom_ctl function in
  drivers/scsi/qla2xxx/qla_attr.c in the Linux kernel allowed local users
  to cause a denial of service (memory corruption and system crash) by
  leveraging root access (bnc#1056588).

  - CVE-2017-12134: The xen_biovec_phys_mergeable function in
  drivers/xen/biomerge.c in Xen might allow local OS guest users to
  corrupt block device data streams and consequently obtain sensitive
  memory information, cause a denial of service, or gain host OS
  privileges by leveraging incorrect block IO merge-ability calculation
  (bnc#1051790 1053919).

  The following non-security bugs were fixed:

  - acpi / scan: Prefer devices without _HID for _ADR matching (git-fixes).

  - alsa: hda - Add stereo mic quirk for Lenovo G50-70 (17aa:3978)
  (bsc#1020657).

  - alsa: hda - Implement mic-mute LED mode enum (bsc#1055013).

  - alsa: hda/realtek - Add support headphone Mic for ALC221 of HP platform
  (bsc#1024405).

  - alsa: ice1712: Add support for STAudio ADCIII (bsc#1048934).

  - alsa: usb-audio: Apply sample rate quirk to Sennheiser headset
  (bsc#1052580).

  - Add 'shutdown' to 'struct class' (bsc#1053117).

  - bluetooth: bnep: fix possible might sleep error in bnep_session
  (bsc#1031784).

  - bluetooth: cmtp: fix possible might sleep error in cmtp_session
  (bsc#1031784).

  - btrfs: fix early ENOSPC due to delalloc (bsc#1049226).

  - nfs: flush data when locking a file to ensure cache coherence for mmap
  (bsc#981309).

  - Revert '/proc/iomem: only expose physical resource addresses to ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"Linux Kernel on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~4.4.87~18.29.2", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs-html", rpm:"kernel-docs-html~4.4.87~18.29.2", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-docs-pdf", rpm:"kernel-docs-pdf~4.4.87~18.29.2", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base-debuginfo", rpm:"kernel-debug-base-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel-debuginfo", rpm:"kernel-debug-devel-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-build-debugsource", rpm:"kernel-obs-build-debugsource~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-obs-qa", rpm:"kernel-obs-qa~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base-debuginfo", rpm:"kernel-vanilla-base-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~4.4.87~18.29.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
