###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2009:1455 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016235.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880765");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2849");
  script_name("CentOS Update for kernel CESA-2009:1455 centos5 i386");

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

  Security fix:

  * a NULL pointer dereference flaw was found in the Multiple Devices (md)
  driver in the Linux kernel. If the 'suspend_lo' or 'suspend_hi' file on the
  sysfs file system ('/sys/') is modified when the disk array is inactive, it
  could lead to a local denial of service or privilege escalation. Note: By
  default, only the root user can write to the files mentioned above.
  (CVE-2009-2849, Moderate)

  Bug fixes:

  * a bug in nlm_lookup_host() could lead to un-reclaimed locks on file
  systems, resulting in umount failing and NFS service relocation issues for
  clusters. (BZ#517967)

  * a bug in the sky2 driver prevented the phy from being reset properly on
  some hardware when it hanged, preventing a link from coming back up.
  (BZ#517976)

  * disabling MSI-X for qla2xxx also disabled MSI interrupts. (BZ#519782)

  * performance issues with reads when using the qlge driver on PowerPC
  systems. A system hang could also occur during reboot. (BZ#519783)

  * unreliable time keeping for Red Hat Enterprise Linux virtual machines.
  The KVM pvclock code is now used to detect/correct lost ticks. (BZ#520685)

  * /proc/cpuinfo was missing flags for new features in supported processors,
  possibly preventing the operating system and applications from getting the
  best performance. (BZ#520686)

  * reading/writing with a serial loopback device on a certain IBM system did
  not work unless booted with 'pnpacpi=off'. (BZ#520905)

  * mlx4_core failed to load on systems with more than 32 CPUs. (BZ#520906)

  * on big-endian platforms, interfaces using the mlx4_en driver and Large
  Receive Offload (LRO) did not handle VLAN traffic properly (a segmentation
  fault in the VLAN stack in the kernel occurred). (BZ#520908)

  * due to a lock being held for a long time, some systems may have
  experienced 'BUG: soft lockup' messages under very heavy load. (BZ#520919)

  * incorrect APIC timer calibration may have caused a system hang during
  boot, as well as the system time becoming faster or slower. A warning is
  now provided. (BZ#521238)

  * a Fibre Channel device re-scan via 'echo '---' > /sys/class/scsi_host/
  host[x]/scan' may not complete after hot adding a drive, leading to soft
  lockups ('BUG: soft lockup detected'). (BZ#521239)

  * the Broadcom BCM5761 network device was unable to be initialized
  properly, therefore, the associated interface could not obtain an IP
  address via DHCP, ...

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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~164.2.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
