###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_0178_1.nasl 13941 2019-02-28 14:35:50Z cfischer $
#
# SuSE Update for the Linux Kernel SUSE-SU-2015:0178-1 (kernel)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850992");
  script_version("$Revision: 13941 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 15:35:50 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-16 16:17:11 +0200 (Fri, 16 Oct 2015)");
  script_cve_id("CVE-2014-3687", "CVE-2014-3690", "CVE-2014-8559", "CVE-2014-9420", "CVE-2014-9585");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for the Linux Kernel SUSE-SU-2015:0178-1 (kernel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.36 to receive
  various security and bugfixes.

  Following security bugs were fixed:

  - CVE-2014-8559: The d_walk function in fs/dcache.c in the Linux kernel
  through 3.17.2 did not properly maintain the semantics of rename_lock,
  which allowed local users to cause a denial of service (deadlock and
  system hang) via a crafted application (bnc#903640).

  - CVE-2014-9420: The rock_continue function in fs/isofs/rock.c in the
  Linux kernel through 3.18.1 did not restrict the number of Rock Ridge
  continuation entries, which allowed local users to cause a denial of
  service (infinite loop, and system crash or hang) via a crafted iso9660
  image (bnc#906545 911325).

  - CVE-2014-3690: arch/x86/kvm/vmx.c in the KVM subsystem in the Linux
  kernel before 3.17.2 on Intel processors did not ensure that the value
  in the CR4 control register remained the same after a VM entry, which
  allowed host OS users to kill arbitrary processes or cause a denial of
  service (system disruption) by leveraging /dev/kvm access, as
  demonstrated by PR_SET_TSC prctl calls within a modified copy of QEMU
  (bnc#902232).

  - CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function in
  net/sctp/associola.c in the SCTP implementation in the Linux kernel
  through 3.17.2 allowed remote attackers to cause a denial of service
  (panic) via duplicate ASCONF chunks that triggered an incorrect uncork
  within the side-effect interpreter (bnc#902349).

  - CVE-2014-9585: The vdso_addr function in arch/x86/vdso/vma.c in the
  Linux kernel through 3.18.2 did not properly choose memory locations for
  the vDSO area, which made it easier for local users to bypass the ASLR
  protection mechanism by guessing a location at the end of a PMD
  (bnc#912705).

  The following non-security bugs were fixed:

  - ACPI idle: permit sparse C-state sub-state numbers (bnc#907969).

  - ALSA: hda - verify pin:converter connection on unsol event for HSW and
  VLV.

  - ALSA: hda - verify pin:cvt connection on preparing a stream for Intel
  HDMI codec.

  - ALSA: hda/hdmi - apply Valleyview fix-ups to Cherryview display codec.

  - ALSA: hda_intel: Add Device IDs for Intel Sunrise Point PCH.

  - ALSA: hda_intel: Add DeviceIDs for Sunrise Point-LP.

  - Btrfs: Disable
  patches.suse/Btrfs-fix-abnormal-long-waiting-in-fsync.patch (bnc#910697)
  because it needs to be revisited due partial msync behavior.

  - Btrfs: Fix misuse of chunk mutex (bnc#912514).

  - Btrfs: always clear a block group node when removing it from the tree
  (bnc#912514).
 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.36~38.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.36~38.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
