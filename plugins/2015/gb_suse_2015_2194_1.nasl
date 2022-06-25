###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_2194_1.nasl 13941 2019-02-28 14:35:50Z cfischer $
#
# SuSE Update for the Linux Kernel SUSE-SU-2015:2194-1 (kernel)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851138");
  script_version("$Revision: 13941 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 15:35:50 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-12-05 08:43:02 +0100 (Sat, 05 Dec 2015)");
  script_cve_id("CVE-2015-0272", "CVE-2015-2925", "CVE-2015-5283", "CVE-2015-5307",
                "CVE-2015-7799", "CVE-2015-7872", "CVE-2015-7990", "CVE-2015-8104",
                "CVE-2015-8215");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for the Linux Kernel SUSE-SU-2015:2194-1 (kernel)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 kernel was updated to 3.12.51 to receive
  various security and bugfixes.

  Following security bugs were fixed:

  - CVE-2015-7799: The slhc_init function in drivers/net/slip/slhc.c in the
  Linux kernel did not ensure that certain slot numbers were valid, which
  allowed local users to cause a denial of service (NULL pointer
  dereference and system crash) via a crafted PPPIOCSMAXCID ioctl call
  (bnc#949936).

  - CVE-2015-5283: The sctp_init function in net/sctp/protocol.c in the
  Linux kernel had an incorrect sequence of protocol-initialization steps,
  which allowed local users to cause a denial of service (panic or memory
  corruption) by creating SCTP sockets before all of the steps have
  finished (bnc#947155).

  - CVE-2015-2925: The prepend_path function in fs/dcache.c in the Linux
  kernel did not properly handle rename actions inside a bind mount, which
  allowed local users to bypass an intended container protection mechanism
  by renaming a directory, related to a 'double-chroot attack (bnc#926238).

  - CVE-2015-8104: The KVM subsystem in the Linux kernel allowed guest OS
  users to cause a denial of service (host OS panic or hang) by triggering
  many #DB (aka Debug) exceptions, related to svm.c (bnc#954404).

  - CVE-2015-5307: The KVM subsystem in the Linux kernel allowed guest OS
  users to cause a denial of service (host OS panic or hang) by triggering
  many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c
  (bnc#953527).

  - CVE-2015-7990: RDS: There was no verification that an underlying
  transport exists when creating a connection, causing usage of a NULL
  pointer (bsc#952384).

  - CVE-2015-7872: The key_gc_unused_keys function in security/keys/gc.c in
  the Linux kernel allowed local users to cause a denial of service (OOPS)
  via crafted keyctl commands (bnc#951440).

  - CVE-2015-0272: Missing checks allowed remote attackers to cause a denial
  of service (IPv6 traffic disruption) via a crafted MTU value in an IPv6
  Router Advertisement (RA) message, a different vulnerability than
  CVE-2015-8215 (bnc#944296).

  The following non-security bugs were fixed:

  - ALSA: hda - Disable 64bit address for Creative HDA controllers
  (bnc#814440).

  - Add PCI IDs of Intel Sunrise Point-H SATA Controller S232/236
  (bsc#953796).

  - Btrfs: fix file corruption and data loss after cloning inline extents
  (bnc#956053).

  - Btrfs: fix truncation of compressed and inlined extents (bnc#956053).

  - Disable some ppc64le netfilter modules to restore the kabi (bsc#951546)

  - Fix regression .

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

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra-debuginfo", rpm:"kernel-default-extra-debuginfo~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.51~52.31.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base-debuginfo", rpm:"kernel-default-base-debuginfo~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base-debuginfo", rpm:"kernel-xen-base-debuginfo~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.12.51~52.31.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
