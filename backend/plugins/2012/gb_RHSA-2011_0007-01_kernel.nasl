###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for kernel RHSA-2011:0007-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-January/msg00005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870652");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-05 19:31:50 +0530 (Tue, 05 Jun 2012)");
  script_cve_id("CVE-2010-2492", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3080",
                "CVE-2010-3298", "CVE-2010-3477", "CVE-2010-3861", "CVE-2010-3865",
                "CVE-2010-3874", "CVE-2010-3876", "CVE-2010-3880", "CVE-2010-4072",
                "CVE-2010-4073", "CVE-2010-4074", "CVE-2010-4075", "CVE-2010-4077",
                "CVE-2010-4079", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4082",
                "CVE-2010-4083", "CVE-2010-4158", "CVE-2010-4160", "CVE-2010-4162",
                "CVE-2010-4163", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4249",
                "CVE-2010-4263", "CVE-2010-4525", "CVE-2010-4668");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("RedHat Update for kernel RHSA-2011:0007-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"kernel on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"* Buffer overflow in eCryptfs. When /dev/ecryptfs has world writable
  permissions (which it does not, by default, on Red Hat Enterprise Linux 6),
  a local, unprivileged user could use this flaw to cause a denial of service
  or possibly escalate their privileges. (CVE-2010-2492, Important)

  * Integer overflow in the RDS protocol implementation could allow a local,
  unprivileged user to cause a denial of service or escalate their
  privileges. (CVE-2010-3865, Important)

  * Missing boundary checks in the PPP over L2TP sockets implementation could
  allow a local, unprivileged user to cause a denial of service or escalate
  their privileges. (CVE-2010-4160, Important)

  * NULL pointer dereference in the igb driver. If both Single Root I/O
  Virtualization (SR-IOV) and promiscuous mode were enabled on an interface
  using igb, it could result in a denial of service when a tagged VLAN packet
  is received on that interface. (CVE-2010-4263, Important)

  * Missing initialization flaw in the XFS file system implementation, and in
  the network traffic policing implementation, could allow a local,
  unprivileged user to cause an information leak. (CVE-2010-3078,
  CVE-2010-3477, Moderate)

  * NULL pointer dereference in the Open Sound System compatible sequencer
  driver could allow a local, unprivileged user with access to /dev/sequencer
  to cause a denial of service. /dev/sequencer is only accessible to root and
  users in the audio group by default. (CVE-2010-3080, Moderate)

  * Flaw in the ethtool IOCTL handler could allow a local user to cause an
  information leak. (CVE-2010-3861, Moderate)

  * Flaw in bcm_connect() in the Controller Area Network (CAN) Broadcast
  Manager. On 64-bit systems, writing the socket address may overflow the
  procname character array. (CVE-2010-3874, Moderate)

  * Flaw in the module for monitoring the sockets of INET transport
  protocols could allow a local, unprivileged user to cause a denial of
  service. (CVE-2010-3880, Moderate)

  * Missing boundary checks in the block layer implementation could allow a
  local, unprivileged user to cause a denial of service. (CVE-2010-4162,
  CVE-2010-4163, CVE-2010-4668, Moderate)

  * NULL pointer dereference in the Bluetooth HCI UART driver could allow a
  local, unprivileged user to cause a denial of service. (CVE-2010-4242,
  Moderate)

  * Flaw in the Linux kernel CPU time clocks implementation for the POSIX
  clock interface could allow a local, unprivileged user to caus ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-debuginfo", rpm:"kernel-debug-debuginfo~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debug-devel", rpm:"kernel-debug-devel~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo", rpm:"kernel-debuginfo~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-i686", rpm:"kernel-debuginfo-common-i686~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-headers", rpm:"kernel-headers~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-doc", rpm:"kernel-doc~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-firmware", rpm:"kernel-firmware~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perf", rpm:"perf~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"kernel-debuginfo-common-x86_64", rpm:"kernel-debuginfo-common-x86_64~2.6.32~71.14.1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
