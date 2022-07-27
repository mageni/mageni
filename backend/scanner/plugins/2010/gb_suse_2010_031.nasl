###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2010:031
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The SUSE Linux Enterprise 11 GA Kernel was updated to 2.6.27.48 fixing
  various bugs and security issues.

  CVE-2010-1641: The do_gfs2_set_flags function in fs/gfs2/file.c in the
  Linux kernel does not verify the ownership of a file, which allows
  local users to bypass intended access restrictions via a SETFLAGS
  ioctl request.

  CVE-2010-1087: The nfs_wait_on_request function in fs/nfs/pagelist.c in
  the Linux kernel allows attackers to cause a denial of service (Oops)
  via unknown vectors related to truncating a file and an operation
  that is not interruptible.

  CVE-2010-1643: mm/shmem.c in the Linux kernel, when strict overcommit
  is enabled, does not properly handle the export of shmemfs objects
  by knfsd, which allows attackers to cause a denial of service (NULL
  pointer dereference and knfsd crash) or possibly have unspecified
  other impact via unknown vectors.

  CVE-2010-1437: Race condition in the find_keyring_by_name function
  in security/keys/keyring.c in the Linux kernel allows local users
  to cause a denial of service (memory corruption and system crash)
  or possibly have unspecified other impact via keyctl session commands
  that trigger access to a dead keyring that is undergoing deletion by
  the key_cleanup function.

  CVE-2010-1446: arch/1/mm/fsl_booke_mmu.c in KGDB in the Linux kernel,
  when running on PowerPC, does not properly perform a security check
  for access to a kernel page, which allows local users to overwrite
  arbitrary kernel memory, related to Fsl booke.

  CVE-2010-1162: The release_one_tty function in drivers/char/tty_io.c in
  the Linux kernel omits certain required calls to the put_pid function,
  which has unspecified impact and local attack vectors.

  CVE-2009-4537: drivers/net/r8169.c in the r8169 driver in the Linux
  kernel does not properly check the size of an Ethernet frame that
  exceeds the MTU, which allows remote attackers to (1) cause a denial
  of service (temporary network outage) via a packet with a crafted size,
  in conjunction with certain packets containing A characters and certain
  packets containing E characters; or (2) cause a denial of service
  (system crash) via a packet with a crafted size, in conjunction with
  certain packets containing '0' characters, related to the value of the
  status register and erroneous behavior associated with the RxMaxSize
  register. NOTE: this vulnerability exists because of an incorrect
  fix for CVE-2009-1389. Code execution might be possible.";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "remote denial of service";
tag_affected = "kernel on openSUSE 11.1";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.314188");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-23 16:10:25 +0200 (Fri, 23 Jul 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1389", "CVE-2009-4537", "CVE-2010-1087", "CVE-2010-1162", "CVE-2010-1437", "CVE-2010-1446", "CVE-2010-1641", "CVE-2010-1643");
  script_name("SuSE Update for kernel SUSE-SA:2010:031");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE11.1")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-extra", rpm:"kernel-debug-extra~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~2.6.27.48~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
