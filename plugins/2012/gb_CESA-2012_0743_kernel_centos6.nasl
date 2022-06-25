###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2012:0743 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-June/018694.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881125");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:16:11 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-0044", "CVE-2012-1179", "CVE-2012-2119", "CVE-2012-2121",
                "CVE-2012-2123", "CVE-2012-2136", "CVE-2012-2137", "CVE-2012-2372",
                "CVE-2012-2373");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2012:0743 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A local, unprivileged user could use an integer overflow flaw in
  drm_mode_dirtyfb_ioctl() to cause a denial of service or escalate their
  privileges. (CVE-2012-0044, Important)

  * A buffer overflow flaw was found in the macvtap device driver, used for
  creating a bridged network between the guest and the host in KVM
  (Kernel-based Virtual Machine) environments. A privileged guest user in a
  KVM guest could use this flaw to crash the host. Note: This issue only
  affected hosts that have the vhost_net module loaded with the
  experimental_zcopytx module option enabled (it is not enabled by default),
  and that also have macvtap configured for at least one guest.
  (CVE-2012-2119, Important)

  * When a set user ID (setuid) application is executed, certain personality
  flags for controlling the application's behavior are cleared (that is, a
  privileged application will not be affected by those flags). It was found
  that those flags were not cleared if the application was made privileged
  via file system capabilities. A local, unprivileged user could use this
  flaw to change the behavior of such applications, allowing them to bypass
  intended restrictions. Note that for default installations, no application
  shipped by Red Hat for Red Hat Enterprise Linux is made privileged via file
  system capabilities. (CVE-2012-2123, Important)

  * It was found that the data_len parameter of the sock_alloc_send_pskb()
  function in the Linux kernel's networking implementation was not validated
  before use. A privileged guest user in a KVM guest could use this flaw to
  crash the host or, possibly, escalate their privileges on the host.
  (CVE-2012-2136, Important)

  * A buffer overflow flaw was found in the setup_routing_entry() function in
  the KVM subsystem of the Linux kernel in the way the Message Signaled
  Interrupts (MSI) routing entry was handled. A local, unprivileged user
  could use this flaw to cause a denial of service or, possibly, escalate
  their privileges. (CVE-2012-2137, Important)

  * A race condition was found in the Linux kernel's memory management
  subsystem in the way pmd_none_or_clear_bad(), when called with mmap_sem in
  read mode, and Transparent Huge Pages (THP) page faults interacted. A
  privileged user in a KVM guest with the ballooning functionality enabled
  could potentially use this flaw to crash the host. A local, unprivileged
  user could use this flaw to crash the system. (CVE-2012-1179, Moderate) ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~220.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
