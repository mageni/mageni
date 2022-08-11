###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2010:0936 centos4 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-January/017223.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880462");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-01-31 15:15:14 +0100 (Mon, 31 Jan 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2010-3432", "CVE-2010-3442");
  script_name("CentOS Update for kernel CESA-2010:0936 centos4 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"kernel on CentOS 4");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  Security fixes:

  * A flaw in sctp_packet_config() in the Linux kernel's Stream Control
  Transmission Protocol (SCTP) implementation could allow a remote attacker
  to cause a denial of service. (CVE-2010-3432, Important)

  * A missing integer overflow check in snd_ctl_new() in the Linux kernel's
  sound subsystem could allow a local, unprivileged user on a 32-bit system
  to cause a denial of service or escalate their privileges. (CVE-2010-3442,
  Important)

  Red Hat would like to thank Dan Rosenberg for reporting CVE-2010-3442.

  Bug fixes:

  * Forward time drift was observed on virtual machines using PM
  timer-based kernel tick accounting and running on KVM or the Microsoft
  Hyper-V Server hypervisor. Virtual machines that were booted with the
  divider=x kernel parameter set to a value greater than 1 and that showed
  the following in the kernel boot messages were subject to this issue:

  time.c: Using PM based timekeeping

  Fine grained accounting for the PM timer is introduced which eliminates
  this issue. However, this fix uncovered a bug in the Xen hypervisor,
  possibly causing backward time drift. If this erratum is installed in Xen
  HVM guests that meet the aforementioned conditions, it is recommended that
  the host use kernel-xen-2.6.18-194.26.1.el5 or newer, which includes a fix
  (BZ#641915) for the backward time drift. (BZ#629237)

  * With multipath enabled, systems would occasionally halt when the
  do_cciss_request function was used. This was caused by wrongly-generated
  requests. Additional checks have been added to avoid the aforementioned
  issue. (BZ#640193)

  * A Sun X4200 system equipped with a QLogic HBA spontaneously rebooted and
  logged a Hyper-Transport Sync Flood Error to the system event log. A
  Maximum Memory Read Byte Count restriction was added to fix this bug.
  (BZ#640919)

  * For an active/backup bonding network interface with VLANs on top of it,
  when a link failed over, it took a minute for the multicast domain to be
  rejoined. This was caused by the driver not sending any IGMP join packets.
  The driver now sends IGMP join packets and the multicast domain is rejoined
  immediately. (BZ#641002)

  * Replacing a disk and trying to rebuild it afterwards caused the system to
  panic. When a domain validation request for a hot plugged drive was sent,
  the mptscsi driver did not validate its existence. This could result in the
  driver accessing random memory and causing the crash. A check has been
  added that describes the new ...

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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem", rpm:"kernel-hugemem~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-hugemem-devel", rpm:"kernel-hugemem-devel~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp-devel", rpm:"kernel-smp-devel~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU", rpm:"kernel-xenU~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xenU-devel", rpm:"kernel-xenU-devel~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.9~89.33.1.EL", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
