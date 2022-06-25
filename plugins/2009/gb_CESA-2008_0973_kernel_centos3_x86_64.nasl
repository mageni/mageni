###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2008:0973 centos3 x86_64
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

  This update addresses the following security issues:
  
  * Tavis Ormandy discovered a deficiency in the Linux kernel 32-bit and
  64-bit emulation. This could allow a local, unprivileged user to prepare
  and run a specially-crafted binary which would use this deficiency to leak
  uninitialized and potentially sensitive data. (CVE-2008-0598, Important)
  
  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local,
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)
  
  * missing capability checks were found in the SBNI WAN driver which could
  allow a local user to bypass intended capability restrictions.
  (CVE-2008-3525, Important)
  
  * the do_truncate() and generic_file_splice_write() functions did not clear
  the setuid and setgid bits. This could allow a local, unprivileged user to
  obtain access to privileged information. (CVE-2008-4210, Important)
  
  * a buffer overflow flaw was found in Integrated Services Digital Network
  (ISDN) subsystem. A local, unprivileged user could use this flaw to cause a
  denial of service. (CVE-2007-6063, Moderate)
  
  * multiple NULL pointer dereferences were found in various Linux kernel
  network drivers. These drivers were missing checks for terminal validity,
  which could allow privilege escalation. (CVE-2008-2812, Moderate)
  
  * a deficiency was found in the Linux kernel virtual filesystem (VFS)
  implementation. This could allow a local, unprivileged user to attempt file
  creation within deleted directories, possibly causing a denial of service.
  (CVE-2008-3275, Moderate)
  
  This update also fixes the following bugs:
  
  * the incorrect kunmap function was used in nfs_xdr_readlinkres. kunmap()
  was used where kunmap_atomic() should have been. As a consequence, if an
  NFSv2 or NFSv3 server exported a volume containing a symlink which included
  a path equal to or longer than the local system's PATH_MAX, accessing the
  link caused a kernel oops. This has been corrected in this update.
  
  * mptctl_gettargetinfo did not check if pIoc3 was NULL before using it as a
  pointer. This caused a kernel panic in mptctl_gettargetinfo in some
  circumstances. A check has been added which prevents this.
  
  * lost tick compensation code in the timer interrupt routine triggered
  without apparent cause. When running as a fully-virtualized client, this
  spurious triggering caused the 64-bit version of Red Hat Enterprise Linux 3
  to present hig ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on CentOS 3";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-December/015502.html");
  script_oid("1.3.6.1.4.1.25623.1.0.311682");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2008-4210", "CVE-2008-3275", "CVE-2008-0598", "CVE-2008-2136", "CVE-2008-2812", "CVE-2007-6063", "CVE-2008-3525");
  script_name( "CentOS Update for kernel CESA-2008:0973 centos3 x86_64");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.4.21~58.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.4.21~58.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.4.21~58.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-unsupported", rpm:"kernel-smp-unsupported~2.4.21~58.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.4.21~58.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-unsupported", rpm:"kernel-unsupported~2.4.21~58.EL", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
