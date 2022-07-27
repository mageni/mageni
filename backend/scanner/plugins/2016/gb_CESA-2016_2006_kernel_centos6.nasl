###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2016:2006 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882574");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-06 06:55:55 +0200 (Thu, 06 Oct 2016)");
  script_cve_id("CVE-2016-4470", "CVE-2016-5829");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2016:2006 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * A flaw was found in the Linux kernel's keyring handling code, where in
key_reject_and_link() an uninitialized variable would eventually lead to
arbitrary free address which could allow attacker to use a use-after-free
style attack. (CVE-2016-4470, Important)

  * A heap-based buffer overflow vulnerability was found in the Linux
kernel's hiddev driver. This flaw could allow a local attacker to corrupt
kernel memory, possible privilege escalation or crashing the system.
(CVE-2016-5829, Moderate)

The CVE-2016-4470 issue was discovered by David Howells (Red Hat Inc.).

Bug Fix(es):

  * Previously, when two NFS shares with different security settings were
mounted, the I/O operations to the kerberos-authenticated mount caused the
RPC_CRED_KEY_EXPIRE_SOON parameter to be set, but the parameter was not
unset when performing the I/O operations on the sec=sys mount.
Consequently, writes to both NFS shares had the same parameters, regardless
of their security settings. This update fixes this problem by moving the
NO_CRKEY_TIMEOUT parameter to the auth- au_flags field. As a result, NFS
shares with different security settings are now handled as expected.
(BZ#1366962)

  * In some circumstances, resetting a Fibre Channel over Ethernet (FCoE)
interface could lead to a kernel panic, due to invalid information
extracted from the FCoE header. This update adds santiy checking to the cpu
number extracted from the FCoE header. This ensures that subsequent
operations address a valid cpu, and eliminates the kernel panic.
(BZ#1359036)

  * Prior to this update, the following problems occurred with the way GSF2
transitioned files and directories from the 'unlinked' state to the 'free'
state:

The numbers reported for the df and the du commands in some cases got out
of sync, which caused blocks in the file system to appear missing. The
blocks were not actually missing, but they were left in the 'unlinked'
state.

In some circumstances, GFS2 referenced a cluster lock that was already
deleted, which led to a kernel panic.

If an object was deleted and its space reused as a different object, GFS2
sometimes deleted the existing one, which caused file system corruption.

With this update, the transition from 'unlinked' to 'free' state has been
fixed. As a result, none of these three problems occur anymore.
(BZ#1359037)

  * Previously, the GFS2 file system in some cases became unresponsive due to
lock dependency problems between inodes and the cluster lock. This occurred
most frequently on nearly full file systems where files and ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-October/022117.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~642.6.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
