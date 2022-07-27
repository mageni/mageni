###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_0206_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for kernel openSUSE-SU-2012:0206-1 (kernel)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850253");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-08-02 22:52:42 +0530 (Thu, 02 Aug 2012)");
  script_cve_id("CVE-2011-1576", "CVE-2011-1770", "CVE-2011-2203", "CVE-2011-2213",
                "CVE-2011-2525", "CVE-2011-2534", "CVE-2011-2699", "CVE-2011-2723",
                "CVE-2011-2898", "CVE-2011-4081", "CVE-2011-4604", "CVE-2010-3880",
                "CVE-2011-1478");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("SuSE Update for kernel openSUSE-SU-2012:0206-1 (kernel)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.3");
  script_tag(name:"affected", value:"kernel on openSUSE 11.3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The openSUSE 11.3 kernel was updated to fix various bugs
  and security issues.

  Following security issues have been fixed: CVE-2011-4604:
  If root does read() on a specific socket, it's possible to
  corrupt (kernel) memory over network, with an ICMP packet,
  if the B.A.T.M.A.N. mesh protocol is used.

  CVE-2011-2525: A flaw allowed the tc_fill_qdisc() function
  in the Linux kernels packet scheduler API implementation to
  be called on built-in qdisc structures. A local,
  unprivileged user could have used this flaw to trigger a
  NULL pointer dereference, resulting in a denial of service.

  CVE-2011-2699: Fernando Gont discovered that the IPv6 stack
  used predictable fragment identification numbers. A remote
  attacker could exploit this to exhaust network resources,
  leading to a denial of service.

  CVE-2011-2213: The inet_diag_bc_audit function in
  net/ipv4/inet_diag.c in the Linux kernel did not properly
  audit INET_DIAG bytecode, which allowed local users to
  cause a denial of service (kernel infinite loop) via
  crafted INET_DIAG_REQ_BYTECODE instructions in a netlink
  message, as demonstrated by an INET_DIAG_BC_JMP instruction
  with a zero yes value, a different vulnerability than
  CVE-2010-3880.

  CVE-2011-1576: The Generic Receive Offload (GRO)
  implementation in the Linux kernel allowed remote attackers
  to cause a denial of service via crafted VLAN packets that
  are processed by the napi_reuse_skb function, leading to
  (1) a memory leak or (2) memory corruption, a different
  vulnerability than CVE-2011-1478.

  CVE-2011-2534: Buffer overflow in the clusterip_proc_write
  function in net/ipv4/netfilter/ipt_CLUSTERIP.c in the Linux
  kernel might have allowed local users to cause a denial of
  service or have unspecified other impact via a crafted
  write operation, related to string data that lacks a
  terminating '\0' character.

  CVE-2011-1770: Integer underflow in the dccp_parse_options
  function (net/dccp/options.c) in the Linux kernel allowed
  remote attackers to cause a denial of service via a
  Datagram Congestion Control Protocol (DCCP) packet with an
  invalid feature options length, which triggered a buffer
  over-read.

  CVE-2011-2723: The skb_gro_header_slow function in
  include/linux/netdevice.h in the Linux kernel, when Generic
  Receive Offload (GRO) is enabled, reset certain fields in
  incorrect situations, which allowed remote attackers to
  cause a denial of service (system crash) via crafted
  network traffic.

  CVE-2011-2898: A kernel information leak in the AF_PACKET
  protocol was fixed which might have allowed local attackers

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.3")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-base", rpm:"kernel-debug-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop", rpm:"kernel-desktop~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-base", rpm:"kernel-desktop-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-desktop-devel", rpm:"kernel-desktop-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-ec2-extra", rpm:"kernel-ec2-extra~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla", rpm:"kernel-vanilla~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-base", rpm:"kernel-vanilla-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vanilla-devel", rpm:"kernel-vanilla-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"preload-kmp-default", rpm:"preload-kmp-default~1.1_k2.6.34.10_0.6~19.1.37", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"preload-kmp-desktop", rpm:"preload-kmp-desktop~1.1_k2.6.34.10_0.6~19.1.37", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source-vanilla", rpm:"kernel-source-vanilla~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vmi-base", rpm:"kernel-vmi-base~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-vmi-devel", rpm:"kernel-vmi-devel~2.6.34.10~0.6.1", rls:"openSUSE11.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
