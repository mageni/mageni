###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2015:1137 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882205");
  script_version("$Revision: 14095 $");
  script_cve_id("CVE-2014-9420", "CVE-2014-9529", "CVE-2014-9584", "CVE-2015-1573",
                "CVE-2015-1593", "CVE-2015-1805", "CVE-2015-2830");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-24 06:16:44 +0200 (Wed, 24 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2015:1137 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
  the core of any Linux operating system.

  * It was found that the Linux kernel's implementation of vectored pipe read
and write functionality did not take into account the I/O vectors that were
already processed when retrying after a failed atomic access operation,
potentially resulting in memory corruption due to an I/O vector array
overrun. A local, unprivileged user could use this flaw to crash the system
or, potentially, escalate their privileges on the system. (CVE-2015-1805,
Important)

  * A race condition flaw was found in the way the Linux kernel keys
management subsystem performed key garbage collection. A local attacker
could attempt accessing a key while it was being garbage collected, which
would cause the system to crash. (CVE-2014-9529, Moderate)

  * A flaw was found in the way the Linux kernel's 32-bit emulation
implementation handled forking or closing of a task with an 'int80' entry.
A local user could potentially use this flaw to escalate their privileges
on the system. (CVE-2015-2830, Low)

  * It was found that the Linux kernel's ISO file system implementation did
not correctly limit the traversal of Rock Ridge extension Continuation
Entries (CE). An attacker with physical access to the system could use this
flaw to trigger an infinite loop in the kernel, resulting in a denial of
service. (CVE-2014-9420, Low)

  * An information leak flaw was found in the way the Linux kernel's ISO9660
file system implementation accessed data on an ISO9660 image with RockRidge
Extension Reference (ER) records. An attacker with physical access to the
system could use this flaw to disclose up to 255 bytes of kernel memory.
(CVE-2014-9584, Low)

  * A flaw was found in the way the nft_flush_table() function of the Linux
kernel's netfilter tables implementation flushed rules that were
referencing deleted chains. A local user who has the CAP_NET_ADMIN
capability could use this flaw to crash the system. (CVE-2015-1573, Low)

  * An integer overflow flaw was found in the way the Linux kernel randomized
the stack for processes on certain 64-bit architecture systems, such as
x86-64, causing the stack entropy to be reduced by four. (CVE-2015-1593,
Low)

Red Hat would like to thank Carl Henrik Lunde for reporting CVE-2014-9420
and CVE-2014-9584. The security impact of the CVE-2015-1805 issue was
discovered by Red Hat.

This update also fixes several bugs. Documentation for these changes is
available from the linked Knowledgebase article.

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. The system must be
rebooted for this update to take effect.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-June/021215.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/1469163");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~229.7.2.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
