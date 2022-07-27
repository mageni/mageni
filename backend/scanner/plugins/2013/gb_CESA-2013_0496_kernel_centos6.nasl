###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2013:0496 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019361.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881682");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 10:02:55 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2012-4508", "CVE-2012-4542", "CVE-2013-0190", "CVE-2013-0309", "CVE-2013-0310", "CVE-2013-0311");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:0496 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * A race condition was found in the way asynchronous I/O and fallocate()
  interacted when using the ext4 file system. A local, unprivileged user
  could use this flaw to expose random data from an extent whose data blocks
  have not yet been written, and thus contain data from a deleted file.
  (CVE-2012-4508, Important)

  * A flaw was found in the way the vhost kernel module handled descriptors
  that spanned multiple regions. A privileged guest user in a KVM guest could
  use this flaw to crash the host or, potentially, escalate their privileges
  on the host. (CVE-2013-0311, Important)

  * It was found that the default SCSI command filter does not accommodate
  commands that overlap across device classes. A privileged guest user could
  potentially use this flaw to write arbitrary data to a LUN that is
  passed-through as read-only. (CVE-2012-4542, Moderate)

  * A flaw was found in the way the xen_failsafe_callback() function in the
  Linux kernel handled the failed iret (interrupt return) instruction
  notification from the Xen hypervisor. An unprivileged user in a 32-bit
  para-virtualized guest could use this flaw to crash the guest.
  (CVE-2013-0190, Moderate)

  * A flaw was found in the way pmd_present() interacted with PROT_NONE
  memory ranges when transparent hugepages were in use. A local, unprivileged
  user could use this flaw to crash the system. (CVE-2013-0309, Moderate)

  * A flaw was found in the way CIPSO (Common IP Security Option) IP options
  were validated when set from user mode. A local user able to set CIPSO IP
  options on the socket could use this flaw to crash the system.
  (CVE-2013-0310, Moderate)

  Red Hat would like to thank Theodore Ts'o for reporting CVE-2012-4508, and
  Andrew Cooper of Citrix for reporting CVE-2013-0190. Upstream acknowledges
  Dmitry Monakhov as the original reporter of CVE-2012-4508. The
  CVE-2012-4542 issue was discovered by Paolo Bonzini of Red Hat.

  This update also fixes several hundred bugs and adds enhancements. Refer to
  the Red Hat Enterprise Linux 6.4 Release Notes for information on the most
  significant of these changes, and the Technical Notes for further
  information, both linked to in the References.

  All Red Hat Enterprise Linux 6 users are advised to install these updated
  packages, which correct these issues, and fix the bugs and add the
  enhancements noted in the Red Hat Enterprise Linux 6.4 Release Notes and
  Technical Notes. The system must be rebooted for this update to take
  effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~358.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
