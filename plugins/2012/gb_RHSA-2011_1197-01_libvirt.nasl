###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libvirt RHSA-2011:1197-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-August/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870687");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:47:23 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-2511");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_name("RedHat Update for libvirt RHSA-2011:1197-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"libvirt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems. In
  addition, libvirt provides tools for remotely managing virtualized systems.

  An integer overflow flaw was found in libvirtd's RPC call handling. An
  attacker able to establish read-only connections to libvirtd could trigger
  this flaw by calling virDomainGetVcpus() with specially-crafted parameters,
  causing libvirtd to crash. (CVE-2011-2511)

  This update also fixes the following bugs:

  * Previously, when the 'virsh vol-create-from' command was run on an LVM
  (Logical Volume Manager) storage pool, performance of the command was very
  low and the operation consumed an excessive amount of time. This bug has
  been fixed in the virStorageVolCreateXMLFrom() function, and the
  performance problem of the command no longer occurs.

  * Due to a regression, libvirt used undocumented command line options,
  instead of the recommended ones. Consequently, the qemu-img utility used an
  invalid argument while creating an encrypted volume, and the process
  eventually failed. With this update, the bug in the backing format of the
  storage back end has been fixed, and encrypted volumes can now be created
  as expected. (BZ#726617)

  * Due to a bug in the qemuAuditDisk() function, hot unplug failures were
  never audited, and a hot unplug success was audited as a failure. This bug
  has been fixed, and auditing of disk hot unplug operations now works as
  expected. (BZ#728516)

  * Previously, when a debug process was being activated, the act of
  preparing a debug message ended up with dereferencing a UUID (universally
  unique identifier) prior to the NULL argument check. Consequently, an API
  running the debug process sometimes terminated with a segmentation fault.
  With this update, a patch has been provided to address this issue, and the
  crashes no longer occur in the described scenario. (BZ#728546)

  * The libvirt library uses the 'boot=on' option to mark which disk is
  bootable but it only uses that option if Qemu advertises its support. The
  qemu-kvm utility in Red Hat Enterprise Linux 6.1 removed support for that
  option and libvirt could not use it. As a consequence, when an IDE disk was
  added as the second storage with a virtio disk being set up as the first
  one by default, the operating system tried to boot from the IDE disk rather
  than the virtio disk and either failed to boot w ...

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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.7~18.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.8.7~18.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-debuginfo", rpm:"libvirt-debuginfo~0.8.7~18.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.7~18.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.7~18.el6_1.1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
