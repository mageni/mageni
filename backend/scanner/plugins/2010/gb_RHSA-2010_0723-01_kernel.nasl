###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2010:0723-01
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
tag_insight = "The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:
  
  * A buffer overflow flaw was found in the ecryptfs_uid_hash() function in
  the Linux kernel eCryptfs implementation. On systems that have the eCryptfs
  netlink transport (Red Hat Enterprise Linux 5 does) or where the
  &quot;/dev/ecryptfs&quot; file has world writable permissions (which it does not, by
  default, on Red Hat Enterprise Linux 5), a local, unprivileged user could
  use this flaw to cause a denial of service or possibly escalate their
  privileges. (CVE-2010-2492, Important)
  
  * A miscalculation of the size of the free space of the initial directory
  entry in a directory leaf block was found in the Linux kernel Global File
  System 2 (GFS2) implementation. A local, unprivileged user with write
  access to a GFS2-mounted file system could perform a rename operation on
  that file system to trigger a NULL pointer dereference, possibly resulting
  in a denial of service or privilege escalation. (CVE-2010-2798, Important)
  
  * A flaw was found in the Xen hypervisor implementation when running a
  system that has an Intel CPU without Extended Page Tables (EPT) support.
  While attempting to dump information about a crashing fully-virtualized
  guest, the flaw could cause the hypervisor to crash the host as well. A
  user with permissions to configure a fully-virtualized guest system could
  use this flaw to crash the host. (CVE-2010-2938, Moderate)
  
  * Information leak flaws were found in the Linux kernel's Traffic Control
  Unit implementation. A local attacker could use these flaws to cause the
  kernel to leak kernel memory to user-space, possibly leading to the
  disclosure of sensitive information. (CVE-2010-2942, Moderate)
  
  * A flaw was found in the Linux kernel's XFS file system implementation.
  The file handle lookup could return an invalid inode as valid. If an XFS
  file system was mounted via NFS (Network File System), a local attacker
  could access stale data or overwrite existing data that reused the inodes.
  (CVE-2010-2943, Moderate)
  
  * An integer overflow flaw was found in the extent range checking code in
  the Linux kernel's ext4 file system implementation. A local, unprivileged
  user with write access to an ext4-mounted file system could trigger this
  flaw by writing to a file at a very large file offset, resulting in a local
  denial of service. (CVE-2010-3015, Moderate)
  
  * An information leak flaw was found in the Linux kernel's USB
  implementation. Certain USB erro ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Red Hat Enterprise Linux (v. 5 server)";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/rhsa-announce/2010-September/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313192");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-01 16:10:21 +0200 (Fri, 01 Oct 2010)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:N");
  script_xref(name: "RHSA", value: "2010:0723-01");
  script_cve_id("CVE-2010-1083", "CVE-2010-2492", "CVE-2010-2798", "CVE-2010-2938", "CVE-2010-2942", "CVE-2010-2943", "CVE-2010-3015");
  script_name("RedHat Update for kernel RHSA-2010:0723-01");

  script_tag(name: "summary" , value: "Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms");
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

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-debuginfo", rpm:"kernel-PAE-debuginfo~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common", rpm:"kernel-debuginfo-common~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-debuginfo", rpm:"kernel-xen-debuginfo~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.17.1.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
