###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2016:1847 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882558");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-09-20 05:41:20 +0200 (Tue, 20 Sep 2016)");
  script_cve_id("CVE-2016-3134", "CVE-2016-4997", "CVE-2016-4998");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2016:1847 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux
kernel, the core of any Linux operating system.

Security Fix(es):

  * A security flaw was found in the Linux kernel in the mark_source_chains()
function in 'net/ipv4/netfilter/ip_tables.c'. It is possible for a
user-supplied 'ipt_entry' structure to have a large 'next_offset' field.
This field is not bounds checked prior to writing to a counter value at the
supplied offset. (CVE-2016-3134, Important)

  * A flaw was discovered in processing setsockopt for 32 bit processes on 64
bit systems. This flaw will allow attackers to alter arbitrary kernel
memory when unloading a kernel module. This action is usually restricted to
root-privileged users but can also be leveraged if the kernel is compiled
with CONFIG_USER_NS and CONFIG_NET_NS and the user is granted elevated
privileges. (CVE-2016-4997, Important)

  * An out-of-bounds heap memory access leading to a Denial of Service, heap
disclosure, or further impact was found in setsockopt(). The function call
is normally restricted to root, however some processes with cap_sys_admin
may also be able to trigger this flaw in privileged container environments.
(CVE-2016-4998, Moderate)

Bug Fix(es):

  * In some cases, running the ipmitool command caused a kernel panic due to
a race condition in the ipmi message handler. This update fixes the race
condition, and the kernel panic no longer occurs in the described scenario.
(BZ#1353947)

  * Previously, running I/O-intensive operations in some cases caused the
system to terminate unexpectedly after a null pointer dereference in the
kernel. With this update, a set of patches has been applied to the 3w-9xxx
and 3w-sas drivers that fix this bug. As a result, the system no longer
crashes in the described scenario. (BZ#1362040)

  * Previously, the Stream Control Transmission Protocol (SCTP) sockets did
not inherit the SELinux labels properly. As a consequence, the sockets were
labeled with the unlabeled_t SELinux type which caused SCTP connections to
fail. The underlying source code has been modified, and SCTP connections
now works as expected. (BZ#1354302)

  * Previously, the bnx2x driver waited for transmission completions when
recovering from a parity event, which substantially increased the recovery
time. With this update, bnx2x does not wait for transmission completion in
the described circumstances. As a result, the recovery of bnx2x after a
parity event now takes less time. (BZ#1351972)

Enhancement(s):

  * With this update, the audit subsystem enables filtering of processes by
name besides filtering by PID. Users can now audit by executable name (with
the '-F exe= path-to-executabl ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-September/022085.html");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~327.36.1.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
