###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2014:1843 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882079");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-11-12 06:24:22 +0100 (Wed, 12 Nov 2014)");
  script_cve_id("CVE-2014-3185", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2014:1843 centos6");

  script_tag(name:"summary", value:"Check the version of kernel");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

  * A race condition flaw was found in the way the Linux kernel's KVM
subsystem handled PIT (Programmable Interval Timer) emulation. A guest user
who has access to the PIT I/O ports could use this flaw to crash the host.
(CVE-2014-3611, Important)

  * A memory corruption flaw was found in the way the USB ConnectTech
WhiteHEAT serial driver processed completion commands sent via USB Request
Blocks buffers. An attacker with physical access to the system could use
this flaw to crash the system or, potentially, escalate their privileges on
the system. (CVE-2014-3185, Moderate)

  * It was found that the Linux kernel's KVM subsystem did not handle the VM
exits gracefully for the invept (Invalidate Translations Derived from EPT)
and invvpid (Invalidate Translations Based on VPID) instructions. On hosts
with an Intel processor and invept/invppid VM exit support, an unprivileged
guest user could use these instructions to crash the guest. (CVE-2014-3645,
CVE-2014-3646, Moderate)

Red Hat would like to thank Lars Bull of Google for reporting
CVE-2014-3611, and the Advanced Threat Research team at Intel Security for
reporting CVE-2014-3645 and CVE-2014-3646.

This update also fixes the following bugs:

  * This update fixes several race conditions between PCI error recovery
callbacks and potential calls of the ifup and ifdown commands in the tg3
driver. When triggered, these race conditions could cause a kernel crash.
(BZ#1142570)

  * Previously, GFS2 failed to unmount a sub-mounted GFS2 file system if its
parent was also a GFS2 file system. This problem has been fixed by adding
the appropriate d_op- d_hash() routine call for the last component of the
mount point path in the path name lookup mechanism code (namei).
(BZ#1145193)

  * Due to previous changes in the virtio-net driver, a Red Hat Enterprise
Linux 6.6 guest was unable to boot with the 'mgr_rxbuf=off' option
specified. This was caused by providing the page_to_skb() function with an
incorrect packet length in the driver's Rx path. This problem has been
fixed and the guest in the described scenario can now boot successfully.
(BZ#1148693)

  * When using one of the newer IPSec Authentication Header (AH) algorithms
with Openswan, a kernel panic could occur. This happened because the
maximum truncated ICV length was too small. To fix this problem, the
MAX_AH_AUTH_LEN parameter has been set to 64. (BZ#1149083)

  * A bug in the IPMI driver caused the kernel to panic when an IPMI
interface was removed using the hotmod script. The IPMI driver has been
fixed to properly clean the relev ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-November/020748.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.1.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
