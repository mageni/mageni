###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2013:0594 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019265.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881626");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-08 10:20:27 +0530 (Fri, 08 Mar 2013)");
  script_cve_id("CVE-2012-3400");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for kernel CESA-2013:0594 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"kernel on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The kernel packages contain the Linux kernel, the core of any Linux
  operating system.

  This update fixes the following security issues:

  * Buffer overflow flaws were found in the udf_load_logicalvol() function in
  the Universal Disk Format (UDF) file system implementation in the Linux
  kernel. An attacker with physical access to a system could use these flaws
  to cause a denial of service or escalate their privileges. (CVE-2012-3400,
  Low)

  This update also fixes the following bugs:

  * Previously, race conditions could sometimes occur in interrupt handling
  on the Emulex BladeEngine 2 (BE2) controllers, causing the network adapter
  to become unresponsive. This update provides a series of patches for the
  be2net driver, which prevents the race from occurring. The network cards
  using BE2 chipsets no longer hang due to incorrectly handled interrupt
  events. (BZ#884704)

  * A boot-time memory allocation pool (the DMI heap) is used to keep the
  list of Desktop Management Interface (DMI) devices during the system boot.
  Previously, the size of the DMI heap was only 2048 bytes on the AMD64 and
  Intel 64 architectures and the DMI heap space could become easily depleted
  on some systems, such as the IBM System x3500 M2. A subsequent OOM failure
  could, under certain circumstances, lead to a NULL pointer entry being
  stored in the DMI device list. Consequently, scanning of such a corrupted
  DMI device list resulted in a kernel panic. The boot-time memory allocation
  pool for the AMD64 and Intel 64 architectures has been enlarged to 4096
  bytes and the routines responsible for populating the DMI device list have
  been modified to skip entries if their name string is NULL. The kernel no
  longer panics in this scenario. (BZ#902683)

  * The size of the buffer used to print the kernel taint output on kernel
  panic was too small, which resulted in the kernel taint output not being
  printed completely sometimes. With this update, the size of the buffer has
  been adjusted and the kernel taint output is now displayed properly.
  (BZ#905829)

  * The code to print the kernel taint output contained a typographical
  error. Consequently, the kernel taint output, which is displayed on kernel
  panic, could not provide taint error messages for unsupported hardware.
  This update fixes the typo and the kernel taint output is now displayed
  correctly. (BZ#885063)

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues. The system must be rebooted for this
  update to take effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~348.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
