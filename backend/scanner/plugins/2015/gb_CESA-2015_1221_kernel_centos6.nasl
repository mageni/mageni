###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2015:1221 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882223");
  script_version("$Revision: 14095 $");
  script_cve_id("CVE-2011-5321", "CVE-2015-1593", "CVE-2015-2830", "CVE-2015-2922",
                "CVE-2015-3636");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-07-16 06:19:14 +0200 (Thu, 16 Jul 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:1221 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
  kernel, the core of any Linux
operating system.

  * A NULL pointer dereference flaw was found in the way the Linux kernel's
virtual console implementation handled reference counting when accessing
pseudo-terminal device files (/dev/pts/*). A local, unprivileged attacker
could use this flaw to crash the system. (CVE-2011-5321, Moderate)

  * It was found that the Linux kernel's ping socket implementation did not
properly handle socket unhashing during spurious disconnects, which could
lead to a use-after-free flaw. On x86-64 architecture systems, a local user
able to create ping sockets could use this flaw to crash the system.
On non-x86-64 architecture systems, a local user able to create ping
sockets could use this flaw to escalate their privileges on the system.
(CVE-2015-3636, Moderate)

  * An integer overflow flaw was found in the way the Linux kernel randomized
the stack for processes on certain 64-bit architecture systems, such as
x86-64, causing the stack entropy to be reduced by four. (CVE-2015-1593,
Low)

  * A flaw was found in the way the Linux kernel's 32-bit emulation
implementation handled forking or closing of a task with an 'int80' entry.
A local user could potentially use this flaw to escalate their privileges
on the system. (CVE-2015-2830, Low)

  * It was found that the Linux kernel's TCP/IP protocol suite implementation
for IPv6 allowed the Hop Limit value to be set to a smaller value than the
default one. An attacker on a local network could use this flaw to prevent
systems on that network from sending or receiving network packets.
(CVE-2015-2922, Low)

These updated kernel packages also include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. For information on the most significant of these changes, users
are directed to the referenced article on the Red Hat Customer Portal.

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take effect.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-July/021242.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/1506133");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~504.30.3.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
