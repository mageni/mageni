###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0512_kernel_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for kernel CESA-2018:0512 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882855");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-15 08:46:43 +0100 (Thu, 15 Mar 2018)");
  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for kernel CESA-2018:0512 centos6");
  script_tag(name:"summary", value:"Check the version of kernel");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel,
the core of any Linux operating system.

Security Fix(es):

  * hw: cpu: speculative execution branch target injection (s390-only)
(CVE-2017-5715, Important)

  * hw: cpu: speculative execution bounds-check bypass (s390 and powerpc)
(CVE-2017-5753, Important)

  * hw: cpu: speculative execution permission faults handling (powerpc-only)
(CVE-2017-5754)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fixes:

  * If a fibre channel (FC) switch was powered down and then powered on
again, the SCSI device driver stopped permanently the SCSI device's request
queue. Consequently, the FC port login failed, leaving the port state as
'Bypassed' instead of 'Online', and users had to reboot the operating
system. This update fixes the driver to avoid the permanent stop of the
request queue. As a result, SCSI device now continues working as expected
after power cycling the FC switch. (BZ#1519857)

  * Previously, on final close or unlink of a file, the find_get_pages()
function in the memory management sometimes found no pages even if there
were some pages left to save. Consequently, a kernel crash occurred when
attempting to enter the unlink() function. This update fixes the
find_get_pages() function in the memory management code to not return 0 too
early. As a result, the kernel no longer crashes due to this
behavior.(BZ#1527811)

  * Using IPsec connections under a heavy load could previously lead to a
network performance degradation, especially when using the aesni-intel
module. This update fixes the issue by making the cryptd queue length
configurable so that it can be increased to prevent an overflow and packet
drop. As a result, using IPsec under a heavy load no longer reduces network
performance. (BZ#1527802)

  * Previously, a deadlock in the bnx2fc driver caused all adapters to block
and the SCSI error handler to become unresponsive. As a result, data
transferring through the adapter was sometimes blocked. This update fixes
bnx2fc, and data transferring through the adapter is no longer blocked due
to this behavior. (BZ#1523783)

  * If an NFSv3 client mounted a subdirectory of an exported file system, a
directory entry to the mount hosting the export was incorrectly held even
after clearing the cache. Consequently, attempts to unmount the
subdirectory with the umount command failed with the EBUSY error. With this
update, the underlying source code has been fixed, and the unmount
operation now succeeds as expected in the described situation. (BZ#1535938)

Users of kernel are advised to upgrade to these updated packages, which fix
these bugs. The system must be rebooted for this update to take effect.");
  script_tag(name:"affected", value:"kernel on CentOS 6");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-March/022801.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-abi-whitelists", rpm:"kernel-abi-whitelists~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-perf", rpm:"python-perf~2.6.32~696.23.1.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
