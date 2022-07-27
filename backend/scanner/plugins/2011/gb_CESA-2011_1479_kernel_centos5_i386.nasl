###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for kernel CESA-2011:1479 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-November/018264.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881051");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-12-02 13:30:06 +0530 (Fri, 02 Dec 2011)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2011-1162", "CVE-2011-1898", "CVE-2011-2203", "CVE-2011-2494", "CVE-2011-3363", "CVE-2011-4110");
  script_name("CentOS Update for kernel CESA-2011:1479 centos5 i386");

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

  * Using PCI passthrough without interrupt remapping support allowed Xen
  hypervisor guests to generate MSI interrupts and thus potentially inject
  traps. A privileged guest user could use this flaw to crash the host or
  possibly escalate their privileges on the host. The fix for this issue can
  prevent PCI passthrough working and guests starting. Refer to Red Hat
  Bugzilla bug 715555 for details. (CVE-2011-1898, Important)

  * A flaw was found in the way CIFS (Common Internet File System) shares
  with DFS referrals at their root were handled. An attacker on the local
  network who is able to deploy a malicious CIFS server could create a CIFS
  network share that, when mounted, would cause the client system to crash.
  (CVE-2011-3363, Moderate)

  * A NULL pointer dereference flaw was found in the way the Linux kernel's
  key management facility handled user-defined key types. A local,
  unprivileged user could use the keyctl utility to cause a denial of
  service. (CVE-2011-4110, Moderate)

  * A flaw in the way memory containing security-related data was handled in
  tpm_read() could allow a local, unprivileged user to read the results of a
  previously run TPM command. (CVE-2011-1162, Low)

  * A NULL pointer dereference flaw was found in the Linux kernel's HFS file
  system implementation. A local attacker could use this flaw to cause a
  denial of service by mounting a disk that contains a specially-crafted HFS
  file system with a corrupted MDB extent record. (CVE-2011-2203, Low)

  * The I/O statistics from the taskstats subsystem could be read without
  any restrictions. A local, unprivileged user could use this flaw to gather
  confidential information, such as the length of a password used in a
  process. (CVE-2011-2494, Low)

  Red Hat would like to thank Yogesh Sharma for reporting CVE-2011-3363,
  Peter Huewe for reporting CVE-2011-1162, Clement Lecigne for reporting
  CVE-2011-2203, and Vasiliy Kulikov of Openwall for reporting CVE-2011-2494.

  This update also fixes several bugs and adds one enhancement. Documentation
  for these changes will be available shortly from the Technical Notes
  document linked to in the References section.

  Users should upgrade to these updated packages, which contain backported
  patches to correct these issues, and fix the bugs and add the enhancement
  noted in the Technical Notes. The system must be rebooted for this update
  to take effect.");
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

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE", rpm:"kernel-PAE~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-PAE-devel", rpm:"kernel-PAE-devel~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.18~274.12.1.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
