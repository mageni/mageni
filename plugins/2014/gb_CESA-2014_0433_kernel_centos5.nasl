###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2014:0433 centos5
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
  script_oid("1.3.6.1.4.1.25623.1.0.881926");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-05-02 10:05:17 +0530 (Fri, 02 May 2014)");
  script_cve_id("CVE-2012-6638", "CVE-2013-2888");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for kernel CESA-2014:0433 centos5");

  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

  * A flaw was found in the way the Linux kernel's TCP/IP protocol suite
implementation handled TCP packets with both the SYN and FIN flags set.
A remote attacker could use this flaw to consume an excessive amount of
resources on the target system, potentially resulting in a denial of
service. (CVE-2012-6638, Moderate)

  * A flaw was found in the way the Linux kernel handled HID (Human Interface
Device) reports with an out-of-bounds Report ID. An attacker with physical
access to the system could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2013-2888,
Moderate)

This update also fixes the following bugs:

  * A previous change to the sunrpc code introduced a race condition between
the rpc_wake_up_task() and rpc_wake_up_status() functions. A race between
threads operating on these functions could result in a deadlock situation,
subsequently triggering a 'soft lockup' event and rendering the system
unresponsive. This problem has been fixed by re-ordering tasks in the RPC
wait queue. (BZ#1073731)

  * Running a process in the background on a GFS2 file system could
sometimes trigger a glock recursion error that resulted in a kernel panic.
This happened when a readpage operation attempted to take a glock that had
already been held by another function. To prevent this error, GFS2 now
verifies whether the glock is already held when performing the readpage
operation. (BZ#1073953)

  * A previous patch backport to the IUCV (Inter User Communication Vehicle)
code was incomplete. Consequently, when establishing an IUCV connection,
the kernel could, under certain circumstances, dereference a NULL pointer,
resulting in a kernel panic. A patch has been applied to correct this
problem by calling the proper function when removing IUCV paths.
(BZ#1077045)

In addition, this update adds the following enhancement:

  * The lpfc driver had a fixed timeout of 60 seconds for SCSI task
management commands. With this update, the lpfc driver enables the user to
set this timeout within the range from 5 to 180 seconds. The timeout can
be changed by modifying the 'lpfc_task_mgmt_tmo' parameter for the lpfc
driver. (BZ#1073123)

All kernel users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues and add this
enhancement. The system must be rebooted for this update to take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-April/020268.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~371.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}