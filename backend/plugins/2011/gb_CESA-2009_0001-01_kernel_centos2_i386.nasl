###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:0001-01 centos2 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-February/015576.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880937");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2006-4814", "CVE-2007-2172", "CVE-2007-3848", "CVE-2007-4308",
                "CVE-2007-6063", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007",
                "CVE-2008-2136", "CVE-2008-3275", "CVE-2008-3525", "CVE-2008-4210");
  script_name("CentOS Update for kernel CESA-2009:0001-01 centos2 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS2");
  script_tag(name:"affected", value:"kernel on CentOS 2");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  These updated packages fix the following security issues:

  * a flaw was found in the IPv4 forwarding base. This could allow a local,
  unprivileged user to cause a denial of service. (CVE-2007-2172,
  Important)

  * a flaw was found in the handling of process death signals. This allowed a
  local, unprivileged user to send arbitrary signals to the suid-process
  executed by that user. Successful exploitation of this flaw depends on the
  structure of the suid-program and its signal handling. (CVE-2007-3848,
  Important)

  * when accessing kernel memory locations, certain Linux kernel drivers
  registering a fault handler did not perform required range checks. A local,
  unprivileged user could use this flaw to gain read or write access to
  arbitrary kernel memory, or possibly cause a denial of service.
  (CVE-2008-0007, Important)

  * a possible kernel memory leak was found in the Linux kernel Simple
  Internet Transition (SIT) INET6 implementation. This could allow a local,
  unprivileged user to cause a denial of service. (CVE-2008-2136, Important)

  * missing capability checks were found in the SBNI WAN driver which could
  allow a local, unprivileged user to bypass intended capability
  restrictions. (CVE-2008-3525, Important)

  * a flaw was found in the way files were written using truncate() or
  ftruncate(). This could allow a local, unprivileged user to acquire the
  privileges of a different group and obtain access to sensitive information.
  (CVE-2008-4210, Important)

  * a race condition in the mincore system core allowed a local, unprivileged
  user to cause a denial of service. (CVE-2006-4814, Moderate)

  * a flaw was found in the aacraid SCSI driver. This allowed a local,
  unprivileged user to make ioctl calls to the driver which should otherwise
  be restricted to privileged users. (CVE-2007-4308, Moderate)

  * two buffer overflow flaws were found in the Integrated Services Digital
  Network (ISDN) subsystem. A local, unprivileged user could use these flaws
  to cause a denial of service. (CVE-2007-6063, CVE-2007-6151, Moderate)

  * a flaw was found in the way core dump files were created. If a local,
  unprivileged user could make a root-owned process dump a core file into a
  user-writable directory, the user could gain read access to that core file,
  potentially compromising sensitive information. (CVE-2007-6206, Moderate)

  * a deficiency was found in the Linux kernel virtual file system (VFS)
  implementation. This could allow a local, unprivileged ...

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

if(release == "CentOS2")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-BOOT", rpm:"kernel-BOOT~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-enterprise", rpm:"kernel-enterprise~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-summit", rpm:"kernel-summit~2.4.9~e.74", rls:"CentOS2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
