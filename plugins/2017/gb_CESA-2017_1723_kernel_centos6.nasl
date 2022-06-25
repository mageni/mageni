###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2017:1723 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882752");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-07-14 15:55:27 +0530 (Fri, 14 Jul 2017)");
  script_cve_id("CVE-2017-7895");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2017:1723 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * The NFSv2 and NFSv3 server implementations in the Linux kernel through
4.10.13 lacked certain checks for the end of a buffer. A remote attacker
could trigger a pointer-arithmetic error or possibly cause other
unspecified impacts using crafted requests related to fs/nfsd/nfs3xdr.c and
fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important)

Red Hat would like to thank Ari Kauppi for reporting this issue.

Bug Fix(es):

  * If several file operations were started after a mounted NFS share had got
idle and its Transmission Control Protocol (TCP) connection had therefore
been terminated, these operations could cause multiple TCP SYN packets
coming from the NFS client instead of one. With this update, the
reconnection logic has been fixed, and only one TCP SYN packet is now sent
in the described situation. (BZ#1450850)

  * When the ixgbe driver was loaded for a backplane-connected network card,
a kernel panic could occur, because the ops.setup_fc function pointer was
used before the initialization. With this update, ops.setup_fc is
initialized earlier. As a result, ixgbe no longer panics on load.
(BZ#1457347)

  * When setting an Access Control List (ACL) with 190 and more Access
Control Entries (ACEs) on a NFSv4 directory, a kernel crash could
previously occur. This update fixes the nfs4_getfacl() function, and the
kernel no longer crashes under the described circumstances. (BZ#1449096)

  * When upgrading to kernel with the fix for stack guard flaw, a crash could
occur in Java Virtual Machine (JVM) environments, which attempted to
implement their own stack guard page. With this update, the underlying
source code has been fixed to consider the PROT_NONE mapping as a part of
the stack, and the crash in JVM no longer occurs under the described
circumstances. (BZ#1466667)

  * When a program receives IPv6 packets using the raw socket, the
ioctl(FIONREAD) and ioctl(SIOCINQ) functions can incorrectly return zero
waiting bytes. This update fixes the ip6_input_finish() function to check
the raw payload size properly. As a result, the ioctl() function now
returns bytes waiting in the raw socket correctly. (BZ#1450870)

  * Previously, listing a directory on a non-standard XFS filesystem (with
non-default multi-fsb directory blocks) could lead to a soft lock up due to
array index overrun in the xfs_dir2_leaf_readbuf() function. This update
fixes xfs_dir2_leaf_readbuf(), and the soft lock up no longer occurs under
the described circumstances. (BZ#1445179)

  * Previously, aborts from the array after the Storage Area Network (SAN ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2017-July/022497.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~696.6.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
