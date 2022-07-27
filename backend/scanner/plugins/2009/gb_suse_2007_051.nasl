###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2007_051.nasl 8050 2017-12-08 09:34:29Z santu $
#
# SuSE Update for kernel SUSE-SA:2007:051
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
tag_insight = "The Linux kernel in SLE 10 and SUSE Linux 10.1 was updated to fix
  various security issues and lots of bugs spotted after the Service
  Pack 1 release.

  This again aligns the SUSE Linux 10.1 kernel with the SLE 10 release
  and for 10.1 contains kABI incompatible changes, requiring updated
  kernel module packages.  Our KMPs shipped with SUSE Linux 10.1 were
  released at the same time, the NVIDIA, ATI and madwifi module owners
  have been advised to update their repositories too.

  Following security issues were fixed:
  - CVE-2007-2242: The IPv6 protocol allows remote attackers to cause
  a denial of service via crafted IPv6 type 0 route headers (IPV6_RTHDR_TYPE_0)
  that create network amplification between two routers.

  The default is that RH0 is disabled now. To adjust this, write to
  the file /proc/net/accept_source_route6.

  - CVE-2007-2453: The random number feature in the Linux kernel 2.6 (1)
  did not properly seed pools when there is no entropy, or (2) used
  an incorrect cast when extracting entropy, which might have caused
  the random number generator to provide the same values after reboots
  on systems without an entropy source.

  - CVE-2007-2876: A NULL pointer dereference in SCTP connection tracking
  could be caused by a remote attacker by sending specially crafted
  packets.
  Note that this requires SCTP set-up and active to be exploitable.

  - CVE-2007-3105: Stack-based buffer overflow in the random number
  generator (RNG) implementation in the Linux kernel before 2.6.22
  might allow local root users to cause a denial of service or gain
  privileges by setting the default wake-up threshold to a value
  greater than the output pool size, which triggers writing random
  numbers to the stack by the pool transfer function involving &quot;bound
  check ordering&quot;.

  Since this value can only be changed by a root user, exploitability
  is low.

  - CVE-2007-3107: The signal handling in the Linux kernel, when run on
  PowerPC systems using HTX, allows local users to cause a denial of
  service via unspecified vectors involving floating point corruption
  and concurrency.

  - CVE-2007-2525: Memory leak in the PPP over Ethernet (PPPoE) socket
  implementation in the Linux kernel allowed local users to cause
  a denial of service ( ... 

  Description truncated, for more information please check the Reference URL";

tag_impact = "remote denial of service";
tag_affected = "kernel on SUSE LINUX 10.1, SUSE Linux Enterprise Desktop 10 SP1, SLE SDK 10 SP1, SUSE Linux Enterprise Server 10 SP1";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.311370");
  script_version("$Revision: 8050 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-08 10:34:29 +0100 (Fri, 08 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-01-28 13:40:10 +0100 (Wed, 28 Jan 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2007-2242", "CVE-2007-2453", "CVE-2007-2525", "CVE-2007-2876", "CVE-2007-3105", "CVE-2007-3107", "CVE-2007-3513", "CVE-2007-3848", "CVE-2007-3851");
  script_name( "SuSE Update for kernel SUSE-SA:2007:051");

  script_tag(name:"summary", value:"Check for the Version of kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms");
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

if(release == "SLESDk10SP1")
{

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.53~0.8", rls:"SLESDk10SP1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "SL10.1")
{

  if ((res = isrpmvuln(pkg:"cloop-kmp-bigsmp", rpm:"cloop-kmp-bigsmp~2.01_2.6.16.53_0.8~22.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cloop-kmp-debug", rpm:"cloop-kmp-debug~2.01_2.6.16.53_0.8~22.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cloop-kmp-default", rpm:"cloop-kmp-default~2.01_2.6.16.53_0.8~22.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cloop-kmp-smp", rpm:"cloop-kmp-smp~2.01_2.6.16.53_0.8~22.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cloop-kmp-xen", rpm:"cloop-kmp-xen~2.01_2.6.16.53_0.8~22.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cloop-kmp-xenpae", rpm:"cloop-kmp-xenpae~2.01_2.6.16.53_0.8~22.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd", rpm:"drbd~0.7.22~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-bigsmp", rpm:"drbd-kmp-bigsmp~0.7.22_2.6.16.53_0.8~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-debug", rpm:"drbd-kmp-debug~0.7.22_2.6.16.53_0.8~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-default", rpm:"drbd-kmp-default~0.7.22_2.6.16.53_0.8~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-smp", rpm:"drbd-kmp-smp~0.7.22_2.6.16.53_0.8~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-xen", rpm:"drbd-kmp-xen~0.7.22_2.6.16.53_0.8~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"drbd-kmp-xenpae", rpm:"drbd-kmp-xenpae~0.7.22_2.6.16.53_0.8~42.14", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hbedv-dazuko-kmp-bigsmp", rpm:"hbedv-dazuko-kmp-bigsmp~2.3.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hbedv-dazuko-kmp-debug", rpm:"hbedv-dazuko-kmp-debug~2.3.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hbedv-dazuko-kmp-default", rpm:"hbedv-dazuko-kmp-default~2.3.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hbedv-dazuko-kmp-smp", rpm:"hbedv-dazuko-kmp-smp~2.3.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hbedv-dazuko-kmp-xen", rpm:"hbedv-dazuko-kmp-xen~2.3.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"hbedv-dazuko-kmp-xenpae", rpm:"hbedv-dazuko-kmp-xenpae~2.3.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-bigsmp", rpm:"ivtv-kmp-bigsmp~0.7.0_2.6.16.53_0.8~12.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-debug", rpm:"ivtv-kmp-debug~0.7.0_2.6.16.53_0.8~12.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-default", rpm:"ivtv-kmp-default~0.7.0_2.6.16.53_0.8~12.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-smp", rpm:"ivtv-kmp-smp~0.7.0_2.6.16.53_0.8~12.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-xen", rpm:"ivtv-kmp-xen~0.7.0_2.6.16.53_0.8~12.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ivtv-kmp-xenpae", rpm:"ivtv-kmp-xenpae~0.7.0_2.6.16.53_0.8~12.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-um", rpm:"kernel-um~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.53~0.8", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kexec-tools", rpm:"kexec-tools~1.101~32.42", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-bigsmp", rpm:"lirc-kmp-bigsmp~0.8.0_2.6.16.53_0.8~0.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-default", rpm:"lirc-kmp-default~0.8.0_2.6.16.53_0.8~0.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-smp", rpm:"lirc-kmp-smp~0.8.0_2.6.16.53_0.8~0.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"lirc-kmp-xenpae", rpm:"lirc-kmp-xenpae~0.8.0_2.6.16.53_0.8~0.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mkinitrd", rpm:"mkinitrd~1.2~106.58", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"multipath-tools", rpm:"multipath-tools~0.4.6~25.21", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-bigsmp", rpm:"ndiswrapper-kmp-bigsmp~1.34_2.6.16.53_0.8~1.10", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-debug", rpm:"ndiswrapper-kmp-debug~1.34_2.6.16.53_0.8~1.10", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-default", rpm:"ndiswrapper-kmp-default~1.34_2.6.16.53_0.8~1.10", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-smp", rpm:"ndiswrapper-kmp-smp~1.34_2.6.16.53_0.8~1.10", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-xen", rpm:"ndiswrapper-kmp-xen~1.34_2.6.16.53_0.8~1.10", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ndiswrapper-kmp-xenpae", rpm:"ndiswrapper-kmp-xenpae~1.34_2.6.16.53_0.8~1.10", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novfs-kmp-bigsmp", rpm:"novfs-kmp-bigsmp~2.0.0_2.6.16.53_0.8~3.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novfs-kmp-debug", rpm:"novfs-kmp-debug~2.0.0_2.6.16.53_0.8~3.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novfs-kmp-default", rpm:"novfs-kmp-default~2.0.0_2.6.16.53_0.8~3.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novfs-kmp-smp", rpm:"novfs-kmp-smp~2.0.0_2.6.16.53_0.8~3.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novfs-kmp-xen", rpm:"novfs-kmp-xen~2.0.0_2.6.16.53_0.8~3.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"novfs-kmp-xenpae", rpm:"novfs-kmp-xenpae~2.0.0_2.6.16.53_0.8~3.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-bigsmp-20060126", rpm:"omnibook-kmp-bigsmp-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-debug-20060126", rpm:"omnibook-kmp-debug-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-default-20060126", rpm:"omnibook-kmp-default-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-kdump-20060126", rpm:"omnibook-kmp-kdump-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-smp-20060126", rpm:"omnibook-kmp-smp-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-xen-20060126", rpm:"omnibook-kmp-xen-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"omnibook-kmp-xenpae-20060126", rpm:"omnibook-kmp-xenpae-20060126~2.6.16.53_0.8~0.5", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"open-iscsi", rpm:"open-iscsi~2.0.707~0.25", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"openafs-kmp-xenpae", rpm:"openafs-kmp-xenpae~1.4.0_2.6.16.53_0.8~21.3", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcfclock-kmp-bigsmp", rpm:"pcfclock-kmp-bigsmp~0.44_2.6.16.53_0.8~15.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcfclock-kmp-debug", rpm:"pcfclock-kmp-debug~0.44_2.6.16.53_0.8~15.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcfclock-kmp-default", rpm:"pcfclock-kmp-default~0.44_2.6.16.53_0.8~15.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pcfclock-kmp-smp", rpm:"pcfclock-kmp-smp~0.44_2.6.16.53_0.8~15.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quickcam-kmp-default", rpm:"quickcam-kmp-default~0.6.3_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"smartlink-softmodem-kmp-bigsmp", rpm:"smartlink-softmodem-kmp-bigsmp~2.9.10_2.6.16.53_0.8~44.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"smartlink-softmodem-kmp-default", rpm:"smartlink-softmodem-kmp-default~2.9.10_2.6.16.53_0.8~44.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"smartlink-softmodem-kmp-smp", rpm:"smartlink-softmodem-kmp-smp~2.9.10_2.6.16.53_0.8~44.2", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tpctl-kmp-bigsmp", rpm:"tpctl-kmp-bigsmp~4.17_2.6.16.53_0.8~30.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tpctl-kmp-debug", rpm:"tpctl-kmp-debug~4.17_2.6.16.53_0.8~30.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tpctl-kmp-default", rpm:"tpctl-kmp-default~4.17_2.6.16.53_0.8~30.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tpctl-kmp-smp", rpm:"tpctl-kmp-smp~4.17_2.6.16.53_0.8~30.13", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"udev-085", rpm:"udev-085~30.40", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-bigsmp", rpm:"usbvision-kmp-bigsmp~0.9.8.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-debug", rpm:"usbvision-kmp-debug~0.9.8.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-default", rpm:"usbvision-kmp-default~0.9.8.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-smp", rpm:"usbvision-kmp-smp~0.9.8.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-xen", rpm:"usbvision-kmp-xen~0.9.8.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"usbvision-kmp-xenpae", rpm:"usbvision-kmp-xenpae~0.9.8.2_2.6.16.53_0.8~0.1", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-kmp-bigsmp-1", rpm:"wlan-kmp-bigsmp-1~2.6.16.53_0.8~0.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-kmp-debug-1", rpm:"wlan-kmp-debug-1~2.6.16.53_0.8~0.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-kmp-default-1", rpm:"wlan-kmp-default-1~2.6.16.53_0.8~0.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-kmp-smp-1", rpm:"wlan-kmp-smp-1~2.6.16.53_0.8~0.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-kmp-xen-1", rpm:"wlan-kmp-xen-1~2.6.16.53_0.8~0.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wlan-kmp-xenpae-1", rpm:"wlan-kmp-xenpae-1~2.6.16.53_0.8~0.7", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-kmp-bigsmp", rpm:"zaptel-kmp-bigsmp~1.2.4_2.6.16.53_0.8~10.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-kmp-debug", rpm:"zaptel-kmp-debug~1.2.4_2.6.16.53_0.8~10.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-kmp-default", rpm:"zaptel-kmp-default~1.2.4_2.6.16.53_0.8~10.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-kmp-smp", rpm:"zaptel-kmp-smp~1.2.4_2.6.16.53_0.8~10.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-kmp-xen", rpm:"zaptel-kmp-xen~1.2.4_2.6.16.53_0.8~10.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zaptel-kmp-xenpae", rpm:"zaptel-kmp-xenpae~1.2.4_2.6.16.53_0.8~10.12", rls:"SL10.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
