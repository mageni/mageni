###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2015:1623 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882245");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-5364", "CVE-2015-5366");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-08-14 05:34:33 +0200 (Fri, 14 Aug 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:1623 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
  kernel, the core of any Linux
operating system.

Two flaws were found in the way the Linux kernel's networking
implementation handled UDP packets with incorrect checksum values. A remote
attacker could potentially use these flaws to trigger an infinite loop in
the kernel, resulting in a denial of service on the system, or cause a
denial of service in applications using the edge triggered epoll
functionality. (CVE-2015-5364, CVE-2015-5366, Important)

This update also fixes the following bugs:

  * When removing a directory, and a reference was held to that directory by
a reference to a negative child dentry, the directory dentry was previously
not killed. In addition, once the negative child dentry was killed, an
unlinked and unused dentry was present in the cache. As a consequence,
deadlock could be caused by forcing the dentry eviction while the file
system in question was frozen. With this update, all unused dentries are
unhashed and evicted just after a successful directory removal, which
avoids the deadlock, and the system no longer hangs in the aforementioned
scenario. (BZ#1243400)

  * Due to the broken s_umount lock ordering, a race condition occurred when
an unlinked file was closed and the sync (or syncfs) utility was run at the
same time. As a consequence, deadlock occurred on a frozen file system
between sync and a process trying to unfreeze the file system. With this
update, sync (or syncfs) is skipped on a frozen file system, and deadlock
no longer occurs in the aforementioned situation. (BZ#1243404)

  * Previously, in the scenario when a file was opened by file handle
(fhandle) with its dentry not present in dcache ('cold dcache') and then
making use of the unlink() and close() functions, the inode was not freed
upon the close() system call. As a consequence, the iput() final was
delayed indefinitely. A patch has been provided to fix this bug, and the
inode is now freed as expected. (BZ#1243406)

  * Due to a corrupted Executable and Linkable Format (ELF) header in the
/proc/vmcore file, the kdump utility failed to provide any information.
The underlying source code has been patched, and kdump now provides
debugging information for kernel crashes as intended. (BZ#1245195)

  * Previously, running the multipath request queue caused regressions in
cases where paths failed regularly under I/O load. This regression
manifested as I/O stalls that exceeded 300 seconds. This update reverts the
changes aimed to reduce running the multipath request queue resulting in
I/O stalls completing in a timely manner. (BZ#1246095)

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-August/021327.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~573.3.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
