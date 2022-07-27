###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2011:1189-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-August/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870646");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:39:18 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1182", "CVE-2011-1576", "CVE-2011-1593", "CVE-2011-1776",
                "CVE-2011-1898", "CVE-2011-2183", "CVE-2011-2213", "CVE-2011-2491",
                "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2497", "CVE-2011-2517",
                "CVE-2011-2689", "CVE-2011-2695");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for kernel RHSA-2011:1189-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Security issues:

  * Using PCI passthrough without interrupt remapping support allowed KVM
  guests to generate MSI interrupts and thus potentially inject traps. A
  privileged guest user could use this flaw to crash the host or possibly
  escalate their privileges on the host. The fix for this issue can prevent
  PCI passthrough working and guests starting. Refer to Red Hat Bugzilla bug
  715555 for details. (CVE-2011-1898, Important)

  * Flaw in the client-side NLM implementation could allow a local,
  unprivileged user to cause a denial of service. (CVE-2011-2491, Important)

  * Integer underflow in the Bluetooth implementation could allow a remote
  attacker to cause a denial of service or escalate their privileges by
  sending a specially-crafted request to a target system via Bluetooth.
  (CVE-2011-2497, Important)

  * Buffer overflows in the netlink-based wireless configuration interface
  implementation could allow a local user, who has the CAP_NET_ADMIN
  capability, to cause a denial of service or escalate their privileges on
  systems that have an active wireless interface. (CVE-2011-2517, Important)

  * Flaw in the way the maximum file offset was handled for ext4 file systems
  could allow a local, unprivileged user to cause a denial of service.
  (CVE-2011-2695, Important)

  * Flaw allowed napi_reuse_skb() to be called on VLAN packets. An attacker
  on the local network could use this flaw to send crafted packets to a
  target, possibly causing a denial of service. (CVE-2011-1576, Moderate)

  * Integer signedness error in next_pidmap() could allow a local,
  unprivileged user to cause a denial of service. (CVE-2011-1593, Moderate)

  * Race condition in the memory merging support (KSM) could allow a local,
  unprivileged user to cause a denial of service. KSM is off by default, but
  on systems running VDSM, or on KVM hosts, it is likely turned on by the
  ksm/ksmtuned services. (CVE-2011-2183, Moderate)

  * Flaw in inet_diag_bc_audit() could allow a local, unprivileged user to
  cause a denial of service. (CVE-2011-2213, Moderate)

  * Flaw in the way space was allocated in the Global File System 2 (GFS2)
  implementation. If the file system was almost full, and a local,
  unprivileged user made an fallocate() request, it could result in a denial
  of service. Setting quotas to prevent users from using all available disk
  space would prevent exploitation of this flaw. (CVE-2011-2689, Moderate)

  * Local, unprivileged users could sen ...

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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf-debuginfo", rpm:"perf-debuginfo~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~131.12.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
