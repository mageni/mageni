###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2010:016
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
tag_insight = "The openSUSE 11.0 kernel was updated to fix following security issues:

  CVE-2009-4020: Stack-based buffer overflow in the hfs subsystem in the
  Linux kernel 2.6.32 allows remote attackers to have an unspecified impact
  via a crafted Hierarchical File System (HFS) filesystem, related to the
  hfs_readdir function in fs/hfs/dir.c.

  CVE-2010-0307: The load_elf_binary function in fs/binfmt_elf.c in the
  Linux kernel before 2.6.32.8 on the x86_64 platform does not ensure that
  the ELF interpreter is available before a call to the SET_PERSONALITY
  macro, which allows local users to cause a denial of service (system
  crash) via a 32-bit application that attempts to execute a 64-bit
  application and then triggers a segmentation fault, as demonstrated by
  amd64_killer, related to the flush_old_exec function.

  CVE-2010-0622: The wake_futex_pi function in kernel/futex.c in the
  Linux kernel before 2.6.33-rc7 does not properly handle certain unlock
  operations for a Priority Inheritance (PI) futex, which allows local
  users to cause a denial of service (OOPS) and possibly have unspecified
  other impact via vectors involving modification of the futex value from
  user space.

  CVE-2010-0410: drivers/connector/connector.c in the Linux kernel
  before 2.6.32.8 allows local users to cause a denial of service (memory
  consumption and system crash) by sending the kernel many NETLINK_CONNECTOR
  messages.

  CVE-2010-0415: The do_pages_move function in mm/migrate.c in the Linux
  kernel before 2.6.33-rc7 does not validate node values, which allows
  local users to read arbitrary kernel memory locations, cause a denial of
  service (OOPS), and possibly have unspecified other impact by specifying
  a node that is not part of the kernel's node set.";

tag_impact = "potential local privilege escalation, information disclosure";
tag_affected = "kernel on openSUSE 11.0";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.314504");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-22 11:34:53 +0100 (Mon, 22 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-4020", "CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622");
  script_name("SuSE Update for kernel SUSE-SA:2010:016");

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

if(release == "openSUSE11.0")
{

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debugsource", rpm:"kernel-debug-debugsource~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debuginfo", rpm:"kernel-default-debuginfo~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-debugsource", rpm:"kernel-default-debugsource~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-debuginfo", rpm:"kernel-pae-debuginfo~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-debugsource", rpm:"kernel-pae-debugsource~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-debuginfo", rpm:"kernel-source-debuginfo~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debuginfo", rpm:"kernel-vanilla-debuginfo~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-debugsource", rpm:"kernel-vanilla-debugsource~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debugsource", rpm:"kernel-xen-debugsource~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"acerhk-kmp-debug", rpm:"acerhk-kmp-debug~0.5.35_2.6.25.20_0.7~98.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"acx-kmp-debug-20080210", rpm:"acx-kmp-debug-20080210~2.6.25.20_0.7~4.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"appleir-kmp-debug", rpm:"appleir-kmp-debug~1.1_2.6.25.20_0.7~108.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"at76_usb-kmp-debug", rpm:"at76_usb-kmp-debug~0.17_2.6.25.20_0.7~2.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"atl2-kmp-debug", rpm:"atl2-kmp-debug~2.0.4_2.6.25.20_0.7~4.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"aufs-kmp-debug-cvs20080429", rpm:"aufs-kmp-debug-cvs20080429~2.6.25.20_0.7~13.3", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"dazuko-kmp-debug", rpm:"dazuko-kmp-debug~2.3.4.4_2.6.25.20_0.7~42.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~8.2.6_2.6.25.20_0.7~0.2", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gspcav-kmp-debug", rpm:"gspcav-kmp-debug~01.00.20_2.6.25.20_0.7~1.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"iscsitarget-kmp-debug", rpm:"iscsitarget-kmp-debug~0.4.15_2.6.25.20_0.7~63.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-debug", rpm:"ivtv-kmp-debug~1.0.3_2.6.25.20_0.7~66.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.25.20~0.7", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kqemu-kmp-debug", rpm:"kqemu-kmp-debug~1.3.0pre11_2.6.25.20_0.7~7.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nouveau-kmp-debug", rpm:"nouveau-kmp-debug~0.10.1.20081112_2.6.25.20_0.7~0.4", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-debug-20080313", rpm:"omnibook-kmp-debug-20080313~2.6.25.20_0.7~1.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcc-acpi-kmp-debug", rpm:"pcc-acpi-kmp-debug~0.9_2.6.25.20_0.7~4.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.25.20_0.7~207.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tpctl-kmp-debug", rpm:"tpctl-kmp-debug~4.17_2.6.25.20_0.7~189.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"uvcvideo-kmp-debug-r200", rpm:"uvcvideo-kmp-debug-r200~2.6.25.20_0.7~2.4", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"virtualbox-ose-kmp-debug", rpm:"virtualbox-ose-kmp-debug~1.5.6_2.6.25.20_0.7~33.5", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"vmware-kmp-debug", rpm:"vmware-kmp-debug~2008.04.14_2.6.25.20_0.7~21.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-ng-kmp-debug", rpm:"wlan-ng-kmp-debug~0.2.8_2.6.25.20_0.7~107.1", rls:"openSUSE11.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
