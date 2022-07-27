###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_1852_kernel_centos7.nasl 14095 2019-03-11 13:54:56Z cfischer $
#
# CentOS Update for kernel CESA-2018:1852 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882912");
  script_version("$Revision: 14095 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-06-17 05:52:38 +0200 (Sun, 17 Jun 2018)");
  script_cve_id("CVE-2018-3665");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2018:1852 centos7");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * Kernel: FPU state information leakage via lazy FPU restore
(CVE-2018-3665)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank Julian Stecklina (Amazon.de), Thomas Prescher
(cyberus-technology.de), and Zdenek Sojka (sysgo.com) for reporting this
issue.

4. Solution:

For details on how to apply this update, which includes the changes
described in this advisory, refer to the linked article.

The system must be rebooted for this update to take effect.

5. Bugs fixed:

1585011 - CVE-2018-3665 Kernel: FPU state information leakage via lazy FPU restore

6. Package List:

Red Hat Enterprise Linux Client (v. 7):

Source:
kernel-3.10.0-862.3.3.el7.src.rpm

noarch:
kernel-abi-whitelists-3.10.0-862.3.3.el7.noarch.rpm
kernel-doc-3.10.0-862.3.3.el7.noarch.rpm

x86_64:
kernel-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debug-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debug-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debug-devel-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debuginfo-common-x86_64-3.10.0-862.3.3.el7.x86_64.rpm
kernel-devel-3.10.0-862.3.3.el7.x86_64.rpm
kernel-headers-3.10.0-862.3.3.el7.x86_64.rpm
kernel-tools-3.10.0-862.3.3.el7.x86_64.rpm
kernel-tools-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
kernel-tools-libs-3.10.0-862.3.3.el7.x86_64.rpm
perf-3.10.0-862.3.3.el7.x86_64.rpm
perf-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
python-perf-3.10.0-862.3.3.el7.x86_64.rpm
python-perf-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm

Red Hat Enterprise Linux Client Optional (v. 7):

x86_64:
kernel-debug-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debuginfo-common-x86_64-3.10.0-862.3.3.el7.x86_64.rpm
kernel-tools-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
kernel-tools-libs-devel-3.10.0-862.3.3.el7.x86_64.rpm
perf-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm
python-perf-debuginfo-3.10.0-862.3.3.el7.x86_64.rpm

Red Hat Enterprise Linux ComputeNode (v. 7):

Source:
kernel-3.10.0-862.3.3.el7.src.rpm

noarch:
kernel-abi-whitelists-3.10.0-862.3.3.el7.noarch.rpm
kernel-doc-3.10.0-862.3.3.el7.noarch.rpm

x86_64:
kernel-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debug-3.10.0-862.3.3.el7.x86_64.rpm
kernel-debug-debuginfo-3.10.0-862.3 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"kernel on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-June/022923.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-tools-libs-devel", rpm:"kernel-tools-libs-devel~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~3.10.0~862.3.3.el7", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}