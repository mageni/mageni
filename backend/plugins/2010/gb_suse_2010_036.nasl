###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for kernel SUSE-SA:2010:036
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
tag_insight = "This update fixes various security issues and some bugs in the SUSE Linux
  Enterprise 9 kernel.

  Following security issues were fixed:
  CVE-2010-2521: A crafted NFS write request might have caused a buffer overwrite,
  potentially causing a kernel crash.

  CVE-2008-0598: The x86_64 copy_to_user implementation might have leaked kernel
  memory depending on specific user buffer setups.

  CVE-2009-4537: drivers/net/r8169.c in the r8169 driver in the Linux kernel
  did not properly check the size of an Ethernet frame that exceeds the MTU,
  which allows remote attackers to (1) cause a denial of service (temporary
  network outage) via a packet with a crafted size, in conjunction with
  certain packets containing A characters and certain packets containing E
  characters; or (2) cause a denial of service (system crash) via a packet
  with a crafted size, in conjunction with certain packets containing '\0'
  characters, related to the value of the status register and erroneous
  behavior associated with the RxMaxSize register. NOTE: this vulnerability
  exists because of an incorrect fix for CVE-2009-1389.

  CVE-2010-1188: Use-after-free vulnerability in net/ipv4/tcp_input.c in
  the Linux kernel 2.6 when IPV6_RECVPKTINFO is set on a listening socket,
  allowed remote attackers to cause a denial of service (kernel panic)
  via a SYN packet while the socket is in a listening (TCP_LISTEN) state,
  which is not properly handled causes the skb structure to be freed.

  CVE-2008-3275: The (1) real_lookup and (2) __lookup_hash functions
  in fs/namei.c in the vfs implementation in the Linux kernel did not
  prevent creation of a child dentry for a deleted (aka S_DEAD) directory,
  which allowed local users to cause a denial of service (&quot;overflow&quot; of
  the UBIFS orphan area) via a series of attempted file creations within
  deleted directories.

  CVE-2007-6733: The nfs_lock function in fs/nfs/file.c in the Linux kernel
  did not properly remove POSIX locks on files that are setgid without
  group-execute permission, which allows local users to cause a denial of
  service (BUG and system crash) by locking a file on an NFS filesystem and
  then changing this files permissions, a related issue to CVE-2010-0727.

  CVE-2007-6206: The do_coredump function in fs/exec.c in Linux kernel
  did not change the UID of a core dump file if it exists before a root
  process creates a core dump in the same location, which might have allowed
  local users to obtain sensitive information.

  CVE-2010-1088: fs/namei.c in the Linux kernel did not always follow NFS
  automount &quot;sy ...

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_impact = "remote denial of service";
tag_affected = "kernel on SUSE SLES 9";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.313161");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-10 14:21:00 +0200 (Fri, 10 Sep 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-6206", "CVE-2007-6733", "CVE-2008-0598", "CVE-2008-3275", "CVE-2009-1389", "CVE-2009-4020", "CVE-2009-4537", "CVE-2010-0727", "CVE-2010-1083", "CVE-2010-1088", "CVE-2010-1188", "CVE-2010-2521");
  script_name("SuSE Update for kernel SUSE-SA:2010:036");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
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

if(release == "SLES9.0")
{

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.5~7.323", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.5~7.323", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.5~7.323", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.5~7.323", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.5~7.323", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp", rpm:"xen-kmp~3.0.4_2.6.5_7.323~0.2", rls:"SLES9.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
