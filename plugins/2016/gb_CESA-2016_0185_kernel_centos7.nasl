###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2016:0185 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882396");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-02-17 06:27:32 +0100 (Wed, 17 Feb 2016)");
  script_cve_id("CVE-2015-5157", "CVE-2015-7872");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2016:0185 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

  * It was found that the Linux kernel's keys subsystem did not correctly
garbage collect uninstantiated keyrings. A local attacker could use this
flaw to crash the system or, potentially, escalate their privileges on the
system. (CVE-2015-7872, Important)

  * A flaw was found in the way the Linux kernel handled IRET faults during
the processing of NMIs. An unprivileged, local user could use this flaw to
crash the system or, potentially (although highly unlikely), escalate their
privileges on the system. (CVE-2015-5157, Moderate)

This update also fixes the following bugs:

  * Previously, processing packets with a lot of different IPv6 source
addresses caused the kernel to return warnings concerning soft-lockups due
to high lock contention and latency increase. With this update, lock
contention is reduced by backing off concurrent waiting threads on the
lock. As a result, the kernel no longer issues warnings in the described
scenario. (BZ#1285370)

  * Prior to this update, block device readahead was artificially limited.
As a consequence, the read performance was poor, especially on RAID
devices. Now, per-device readahead limits are used for each device instead
of a global limit. As a result, read performance has improved, especially
on RAID devices. (BZ#1287550)

  * After injecting an EEH error, the host was previously not recovering and
observing I/O hangs in HTX tool logs. This update makes sure that when one
or both of EEH_STATE_MMIO_ACTIVE and EEH_STATE_MMIO_ENABLED flags is marked
in the PE state, the PE's IO path is regarded as enabled as well. As a
result, the host no longer hangs and recovers as expected. (BZ#1289101)

  * The genwqe device driver was previously using the GFP_ATOMIC flag for
allocating consecutive memory pages from the kernel's atomic memory pool,
even in non-atomic situations. This could lead to allocation failures
during memory pressure. With this update, the genwqe driver's memory
allocations use the GFP_KERNEL flag, and the driver can allocate memory
even during memory pressure situations. (BZ#1289450)

  * The nx842 co-processor for IBM Power Systems could in some circumstances
provide invalid data due to a data corruption bug during uncompression.
With this update, all compression and uncompression calls to the nx842
co-processor contain a cyclic redundancy check (CRC) flag, which forces all
compression and uncompression operations to check data integrity and
prevents the co-processor from providing corrupted data. (BZ#1289451)

  * A failed 'updatepp' operation on the little-endian variant o ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-February/021705.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.10.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
