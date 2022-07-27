###############################################################################
# OpenVAS Vulnerability Test
#
# Mandriva Update for kernel MDKSA-2007:171 (kernel)
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
tag_insight = "Some vulnerabilities were discovered and corrected in the Linux
  2.6 kernel:

  The Linux kernel did not properly save or restore EFLAGS during a
  context switch, or reset the flags when creating new threads, which
  allowed local users to cause a denial of service (process crash)
  (CVE-2006-5755).
  
  The compat_sys_mount function in fs/compat.c allowed local users
  to cause a denial of service (NULL pointer dereference and oops)
  by mounting a smbfs file system in compatibility mode (CVE-2006-7203).
  
  The nfnetlink_log function in netfilter allowed an attacker to cause a
  denial of service (crash) via unspecified vectors which would trigger
  a NULL pointer dereference (CVE-2007-1496).
  
  The nf_conntrack function in netfilter did not set nfctinfo during
  reassembly of fragmented packets, which left the default value as
  IP_CT_ESTABLISHED and could allow remote attackers to bypass certain
  rulesets using IPv6 fragments (CVE-2007-1497).
  
  The netlink functionality did not properly handle NETLINK_FIB_LOOKUP
  replies, which allowed a remote attacker to cause a denial of service
  (resource consumption) via unspecified vectors, probably related to
  infinite recursion (CVE-2007-1861).
  
  A typo in the Linux kernel caused RTA_MAX to be used as an array size
  instead of RTN_MAX, which lead to an out of bounds access by certain
  functions (CVE-2007-2172).
  
  The IPv6 protocol allowed remote attackers to cause a denial of
  service via crafted IPv6 type 0 route headers that create network
  amplification between two routers (CVE-2007-2242).
  
  The random number feature did not properly seed pools when there was
  no entropy, or used an incorrect cast when extracting entropy, which
  could cause the random number generator to provide the same values
  after reboots on systems without an entropy source (CVE-2007-2453).
  
  A memory leak in the PPPoE socket implementation allowed local users
  to cause a denial of service (memory consumption) by creating a
  socket using connect, and releasing it before the PPPIOCGCHAN ioctl
  is initialized (CVE-2007-2525).
  
  An integer underflow in the cpuset_tasks_read function, when the cpuset
  filesystem is mounted, allowed local users to obtain kernel memory
  contents by using a large offset when reading the /dev/cpuset/tasks
  file (CVE-2007-2875).
  
  The sctp_new function in netfilter allowed remote attackers to cause
  a denial of service by causing certain invalid states that triggered
  a NULL pointer dereference (CVE-2007-28 ... 

  Description truncated, for more information please check the Reference URL";

tag_affected = "kernel on Mandriva Linux 2007.0,
  Mandriva Linux 2007.0/X86_64,
  Mandriva Linux 2007.1,
  Mandriva Linux 2007.1/X86_64";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.mandriva.com/security-announce/2007-08/msg00017.php");
  script_oid("1.3.6.1.4.1.25623.1.0.304637");
  script_version("$Revision: 6568 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-06 15:04:21 +0200 (Thu, 06 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-04-09 13:57:01 +0200 (Thu, 09 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_xref(name: "MDKSA", value: "2007:171");
  script_cve_id("CVE-2006-5755", "CVE-2006-7203", "CVE-2007-1496", "CVE-2007-1497", "CVE-2007-1861", "CVE-2007-2172", "CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2875", "CVE-2007-2876");
  script_name( "Mandriva Update for kernel MDKSA-2007:171 (kernel)");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release");
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

if(release == "MNDK_2007.1")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc-latest", rpm:"kernel-doc-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise-latest", rpm:"kernel-enterprise-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-latest", rpm:"kernel-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy-latest", rpm:"kernel-legacy-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-latest", rpm:"kernel-source-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped-latest", rpm:"kernel-source-stripped-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0-latest", rpm:"kernel-xen0-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.15mdv~1~1mdv2007.1", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-latest", rpm:"kernel-xenU-latest~2.6.17~15mdv", rls:"MNDK_2007.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "MNDK_2007.0")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-legacy", rpm:"kernel-legacy~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-stripped", rpm:"kernel-source-stripped~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen0", rpm:"kernel-xen0~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.17.15mdv~1~1mdv2007.0", rls:"MNDK_2007.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
