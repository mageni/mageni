###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libvirt RHSA-2015:0323-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871325");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-06 06:49:36 +0100 (Fri, 06 Mar 2015)");
  script_cve_id("CVE-2014-8136", "CVE-2015-0236");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libvirt RHSA-2015:0323-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems.

It was found that QEMU's qemuDomainMigratePerform() and
qemuDomainMigrateFinish2() functions did not correctly perform a domain
unlock on a failed ACL check. A remote attacker able to establish a
connection to libvirtd could use this flaw to lock a domain of a more
privileged user, causing a denial of service. (CVE-2014-8136)

It was discovered that the virDomainSnapshotGetXMLDesc() and
virDomainSaveImageGetXMLDesc() functions did not sufficiently limit the
usage of the VIR_DOMAIN_XML_SECURE flag when fine-grained ACLs were
enabled. A remote attacker able to establish a connection to libvirtd could
use this flaw to obtain certain sensitive information from the domain XML
file. (CVE-2015-0236)

The CVE-2015-0236 issue was found by Luyao Huang of Red Hat.

Bug fixes:

  * The libvirtd daemon previously attempted to search for SELinux contexts
even when SELinux was disabled on the host. Consequently, libvirtd logged
'Unable to lookup SELinux process context' error messages every time a
client connected to libvirtd and SELinux was disabled. libvirtd now
verifies whether SELinux is enabled before searching for SELinux contexts,
and no longer logs the error messages on a host with SELinux disabled.
(BZ#1135155)

  * The libvirt utility passed incomplete PCI addresses to QEMU.
Consequently, assigning a PCI device that had a PCI address with a non-zero
domain to a guest failed. Now, libvirt properly passes PCI domain to QEMU
when assigning PCI devices, which prevents the described problem.
(BZ#1127080)

  * Because the virDomainSetMaxMemory API did not allow changing the current
memory in the LXC driver, the 'virsh setmaxmem' command failed when
attempting to set the maximum memory to be lower than the current memory.
Now, 'virsh setmaxmem' sets the current memory to the intended value of the
maximum memory, which avoids the mentioned problem. (BZ#1091132)

  * Attempting to start a non-existent domain caused network filters to stay
locked for read-only access. Because of this, subsequent attempts to gain
read-write access to network filters triggered a deadlock. Network filters
are now properly unlocked in the described scenario, and the deadlock no
longer occurs. (BZ#1088864)

  * If a guest configuration had an active nwfilter using the DHCP snooping
feature and an attempt was made to terminate libvirtd before the associated
nwfilter rule snooped the guest IP address from DHCP packets, libvirtd
became unresponsive. This problem has been fixed by se ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"libvirt on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-March/msg00023.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon", rpm:"libvirt-daemon~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-config-network", rpm:"libvirt-daemon-config-network~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-config-nwfilter", rpm:"libvirt-daemon-config-nwfilter~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-interface", rpm:"libvirt-daemon-driver-interface~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-lxc", rpm:"libvirt-daemon-driver-lxc~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-network", rpm:"libvirt-daemon-driver-network~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-nodedev", rpm:"libvirt-daemon-driver-nodedev~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-nwfilter", rpm:"libvirt-daemon-driver-nwfilter~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-qemu", rpm:"libvirt-daemon-driver-qemu~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-secret", rpm:"libvirt-daemon-driver-secret~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-driver-storage", rpm:"libvirt-daemon-driver-storage~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-daemon-kvm", rpm:"libvirt-daemon-kvm~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-debuginfo", rpm:"libvirt-debuginfo~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-docs", rpm:"libvirt-docs~1.2.8~16.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
