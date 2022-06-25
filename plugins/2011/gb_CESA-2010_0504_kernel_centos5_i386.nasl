###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2010:0504 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-July/016747.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880617");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-0291", "CVE-2010-0622", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1641");
  script_name("CentOS Update for kernel CESA-2010:0504 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * multiple flaws were found in the mmap and mremap implementations. A local
  user could use these flaws to cause a local denial of service or escalate
  their privileges. (CVE-2010-0291, Important)

  * a NULL pointer dereference flaw was found in the Fast Userspace Mutexes
  (futexes) implementation. The unlock code path did not check if the futex
  value associated with pi_state->owner had been modified. A local user could
  use this flaw to modify the futex value, possibly leading to a denial of
  service or privilege escalation when the pi_state->owner pointer is
  dereferenced. (CVE-2010-0622, Important)

  * a NULL pointer dereference flaw was found in the Linux kernel Network
  File System (NFS) implementation. A local user on a system that has an
  NFS-mounted file system could use this flaw to cause a denial of service or
  escalate their privileges on that system. (CVE-2010-1087, Important)

  * a flaw was found in the sctp_process_unk_param() function in the Linux
  kernel Stream Control Transmission Protocol (SCTP) implementation. A remote
  attacker could send a specially-crafted SCTP packet to an SCTP listening
  port on a target system, causing a kernel panic (denial of service).
  (CVE-2010-1173, Important)

  * a flaw was found in the Linux kernel Transparent Inter-Process
  Communication protocol (TIPC) implementation. If a client application, on a
  local system where the tipc module is not yet in network mode, attempted to
  send a message to a remote TIPC node, it would dereference a NULL pointer
  on the local system, causing a kernel panic (denial of service).
  (CVE-2010-1187, Important)

  * a buffer overflow flaw was found in the Linux kernel Global File System 2
  (GFS2) implementation. In certain cases, a quota could be written past the
  end of a memory page, causing memory corruption, leaving the quota stored
  on disk in an invalid state. A user with write access to a GFS2 file system
  could trigger this flaw to cause a kernel crash (denial of service) or
  escalate their privileges on the GFS2 server. This issue can only be
  triggered if the GFS2 file system is mounted with the 'quota=on' or
  'quota=account' mount option. (CVE-2010-1436, Important)

  * a race condition between finding a keyring by name and destroying a freed
  keyring was found in the Linux kernel key management facility. A local user
  could use this flaw to cause a kernel panic (denial of service) or escalate ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~194.8.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
