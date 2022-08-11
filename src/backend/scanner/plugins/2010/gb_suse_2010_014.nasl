###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2010:014
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
tag_insight = "The SUSE Linux Enterprise 11 and openSUSE 11.1 Kernel were updated to 2.6.27.45 fixing
  various bugs and security issues.

  CVE-2010-0622: The wake_futex_pi function in kernel/futex.c in the
  Linux kernel before 2.6.33-rc7 does not properly handle certain unlock
  operations for a Priority Inheritance (PI) futex, which allows local
  users to cause a denial of service (OOPS) and possibly have unspecified
  other impact via vectors involving modification of the futex value from
  user space.

  CVE-2010-0307: The load_elf_binary function in fs/binfmt_elf.c in the
  Linux kernel before 2.6.32.8 on the x86_64 platform does not ensure that
  the ELF interpreter is available before a call to the SET_PERSONALITY
  macro, which allows local users to cause a denial of service (system
  crash) via a 32-bit application that attempts to execute a 64-bit
  application and then triggers a segmentation fault, as demonstrated by
  amd64_killer, related to the flush_old_exec function.

  CVE-2010-0410: Users could send/allocate arbitrary amounts of
  NETLINK_CONNECTOR messages to the kernel, causing OOM condition, killing
  selected processes or halting the system.

  CVE-2010-0415: The do_pages_move function in mm/migrate.c in the Linux
  kernel before 2.6.33-rc7 does not validate node values, which allows
  local users to read arbitrary kernel memory locations, cause a denial of
  service (OOPS), and possibly have unspecified other impact by specifying
  a node that is not part of the kernels node set.

  CVE-2010-0007: net/bridge/netfilter/ebtables.c in the ebtables module in
  the netfilter framework in the Linux kernel before 2.6.33-rc4 does not
  require the CAP_NET_ADMIN capability for setting or modifying rules, which
  allows local users to bypass intended access restrictions and configure
  arbitrary network-traffic filtering via a modified ebtables application.

  CVE-2009-4536: drivers/net/e1000/e1000_main.c in the e1000 driver in the
  Linux kernel 2.6.32.3 and earlier handles Ethernet frames that exceed
  the MTU by processing certain trailing payload data as if it were a
  complete frame, which allows remote attackers to bypass packet filters
  via a large packet with a crafted payload.

  CVE-2009-4538: drivers/net/e1000e/netdev.c in the e1000e driver in the
  Linux kernel 2.6.32.3 and earlier does not properly check the size of
  an Ethernet frame that exceeds the MTU, which allows remote attackers
  to have an unspecified impact via crafted packets.
  It is not clear if this can be used for code execution.

  CVE-2010-0003: The print_fatal_s ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "potential remote privilege escalation";
tag_affected = "kernel on openSUSE 11.1, SLES 11";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.314549");
  script_version("$Revision: 8244 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-25 08:29:28 +0100 (Mon, 25 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-05 12:48:43 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3939", "CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622");
  script_name("SuSE Update for kernel SUSE-SA:2010:014");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-extra", rpm:"kernel-debug-extra~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~2.6.27.45~0.1.1", rls:"openSUSE11.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
