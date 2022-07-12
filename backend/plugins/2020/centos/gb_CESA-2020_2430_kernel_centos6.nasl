# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.883251");
  script_version("2020-06-12T07:11:22+0000");
  script_cve_id("CVE-2017-12192", "CVE-2020-0543");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-06-12 09:20:35 +0000 (Fri, 12 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-11 03:01:26 +0000 (Thu, 11 Jun 2020)");
  script_name("CentOS: Security Advisory for kernel (CESA-2020:2430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-June/035753.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the CESA-2020:2430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security Fix(es):

  * kernel: NULL pointer dereference due to KEYCTL_READ on negative key
(CVE-2017-12192)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * kernel: hw: provide reporting and microcode mitigation toggle for
CVE-2020-0543 / Special Register Buffer Data Sampling (SRBDS) (BZ#1827185)

  * Bonding not failing over in mode=1 under 2.6.32-754.28.1 (...27.1 works
OK) (BZ#1828604)

1493435 - CVE-2017-12192 kernel: NULL pointer dereference due to KEYCTL_READ on negative key
1828604 - Bonding not failing over in mode=1 under 2.6.32-754.28.1 (...27.1 works OK)

6. Package List:

Red Hat Enterprise Linux Desktop (v. 6):

Source:
kernel-2.6.32-754.30.2.el6.src.rpm

i386:
kernel-2.6.32-754.30.2.el6.i686.rpm
kernel-debug-2.6.32-754.30.2.el6.i686.rpm
kernel-debug-debuginfo-2.6.32-754.30.2.el6.i686.rpm
kernel-debug-devel-2.6.32-754.30.2.el6.i686.rpm
kernel-debuginfo-2.6.32-754.30.2.el6.i686.rpm
kernel-debuginfo-common-i686-2.6.32-754.30.2.el6.i686.rpm
kernel-devel-2.6.32-754.30.2.el6.i686.rpm
kernel-headers-2.6.32-754.30.2.el6.i686.rpm
perf-2.6.32-754.30.2.el6.i686.rpm
perf-debuginfo-2.6.32-754.30.2.el6.i686.rpm
python-perf-debuginfo-2.6.32-754.30.2.el6.i686.rpm

noarch:
kernel-abi-whitelists-2.6.32-754.30.2.el6.noarch.rpm
kernel-doc-2.6.32-754.30.2.el6.noarch.rpm
kernel-firmware-2.6.32-754.30.2.el6.noarch.rpm

x86_64:
kernel-2.6.32-754.30.2.el6.x86_64.rpm
kernel-debug-2.6.32-754.30.2.el6.x86_64.rpm
kernel-debug-debuginfo-2.6.32-754.30.2.el6.i686.rpm
kernel-debug-debuginfo-2.6.32-754.30.2.el6.x86_64.rpm
kernel-debug-devel-2.6.32-754.30.2.el6.i686.rpm
kernel-debug-devel-2.6.32-754.30.2.el6.x86_64.rpm
kernel-debuginfo-2.6.32-754.30.2.el6.i686.rpm
kernel-debuginfo-2.6.32-754.30.2.el6.x86_64.rpm
kernel-debuginfo-common-i686-2.6.32-754.30.2.el6.i686.rpm
kernel-debuginfo-common-x86_64-2.6.32-754.30.2.el6.x86_64.rpm
kernel-devel-2.6.32-754.30.2.el6.x86_64.rpm
kernel-headers-2.6.32-754.30.2.el6.x86_64.rpm
perf-2.6.32-754.30.2.el6.x86_64.rpm
perf-debuginfo-2.6.32-754.30.2.el6.i ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'kernel' package(s) on CentOS 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~754.30.2.el6", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
