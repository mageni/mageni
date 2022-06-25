###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2017:1615-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871838");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-06-29 05:10:09 +0200 (Thu, 29 Jun 2017)");
  script_cve_id("CVE-2017-2583", "CVE-2017-6214", "CVE-2017-7477", "CVE-2017-7645",
                "CVE-2017-7895");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for kernel RHSA-2017:1615-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
  kernel, the core of any Linux operating system. Security Fix(es): * A flaw was
  found in the way Linux kernel allocates heap memory to build the scattergather
  list from a fragment list(skb_shinfo(skb)- frag_list) in the socket
  buffer(skb_buff). The heap overflow occurred if 'MAX_SKB_FRAGS + 1' parameter
  and 'NETIF_F_FRAGLIST' feature were used together. A remote user or process
  could use this flaw to potentially escalate their privilege on a system.
  (CVE-2017-7477, Important) * The NFS2/3 RPC client could send long arguments to
  the NFS server. These encoded arguments are stored in an array of memory pages,
  and accessed using pointer variables. Arbitrarily long arguments could make
  these pointers point outside the array and cause an out-of-bounds memory access.
  A remote user or program could use this flaw to crash the kernel (denial of
  service). (CVE-2017-7645, Important) * The NFSv2 and NFSv3 server
  implementations in the Linux kernel through 4.10.13 lacked certain checks for
  the end of a buffer. A remote attacker could trigger a pointer-arithmetic error
  or possibly cause other unspecified impacts using crafted requests related to
  fs/nfsd/nfs3xdr.c and fs/nfsd/nfsxdr.c. (CVE-2017-7895, Important) * The Linux
  kernel built with the Kernel-based Virtual Machine (CONFIG_KVM) support was
  vulnerable to an incorrect segment selector(SS) value error. The error could
  occur while loading values into the SS register in long mode. A user or process
  inside a guest could use this flaw to crash the guest, resulting in DoS or
  potentially escalate their privileges inside the guest. (CVE-2017-2583,
  Moderate) * A flaw was found in the Linux kernel's handling of packets with the
  URG flag. Applications using the splice() and tcp_splice_read() functionality
  could allow a remote attacker to force the kernel to enter a condition in which
  it could loop indefinitely. (CVE-2017-6214, Moderate) Red Hat would like to
  thank Ari Kauppi for reporting CVE-2017-7895 and Xiaohan Zhang (Huawei Inc.) for
  reporting CVE-2017-2583. Bug Fix(es): * Previously, the reserved-pages counter
  (HugePages_Rsvd) was bigger than the total-pages counter (HugePages_Total) in
  the /proc/meminfo file, and HugePages_Rsvd underflowed. With this update, the
  HugeTLB feature of the Linux kernel has been fixed, and HugePages_Rsvd underflow
  no longer occurs. (BZ#1445184) * If a directory on a NFS client was modified
  while being listed, the NFS client could restart the directory listing multiple
  times. Consequently, the performance of listing the directory was sub-optimal.
  With this up ... Description truncated, for more information please check the
  Reference URL");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-June/msg00060.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-debuginfo", rpm:"kernel-tools-debuginfo~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf-debuginfo", rpm:"python-perf-debuginfo~3.10.0~514.26.1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}