###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2011:1019 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2011-September/017880.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880996");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2011-2511");
  script_name("CentOS Update for libvirt CESA-2011:1019 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libvirt on CentOS 5");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
  virtualization capabilities of Linux and other operating systems.

  An integer overflow flaw was found in libvirtd's RPC call handling. An
  attacker able to establish read-only connections to libvirtd could trigger
  this flaw by calling virDomainGetVcpus() with specially-crafted parameters,
  causing libvirtd to crash. (CVE-2011-2511)

  This update fixes the following bugs:

  * libvirt was rebased from version 0.6.3 to version 0.8.2 in Red Hat
  Enterprise Linux 5.6. A code audit found a minor API change that effected
  error messages seen by libvirt 0.8.2 clients talking to libvirt 0.7.1
  0.7.7 (0.7.x) servers. A libvirt 0.7.x server could send
  VIR_ERR_BUILD_FIREWALL errors where a libvirt 0.8.2 client expected
  VIR_ERR_CONFIG_UNSUPPORTED errors. In other circumstances, a libvirt 0.8.2
  client saw a 'Timed out during operation' message where it should see an
  'Invalid network filter' error. This update adds a backported patch that
  allows libvirt 0.8.2 clients to interoperate with the API as used by
  libvirt 0.7.x servers, ensuring correct error messages are sent.
  (BZ#665075)

  * libvirt could crash if the maximum number of open file descriptors
  (_SC_OPEN_MAX) grew larger than the FD_SETSIZE value because it accessed
  file descriptors outside the bounds of the set. With this update the
  maximum number of open file descriptors can no longer grow larger than the
  FD_SETSIZE value. (BZ#665549)

  * A libvirt race condition was found. An array in the libvirt event
  handlers was accessed with a lock temporarily released. In rare cases, if
  one thread attempted to access this array but a second thread reallocated
  the array before the first thread reacquired a lock, it could lead to the
  first thread attempting to access freed memory, potentially causing libvirt
  to crash. With this update libvirt no longer refers to the old array and,
  consequently, behaves as expected. (BZ#671569)

  * Guests connected to a passthrough NIC would kernel panic if a
  system_reset signal was sent through the QEMU monitor. With this update you
  can reset such guests as expected. (BZ#689880)

  * When using the Xen kernel, the rpmbuild command failed on the xencapstest
  test. With this update you can run rpmbuild successfully when using the Xen
  kernel. (BZ#690459)

  * When a disk was hot unplugged, 'ret >= 0' was passed to the qemuAuditDisk
  calls in disk hotunplug operations before ret was, in fact, set to 0. As
  well, the error path jumped to the 'cleanup&q ...

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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.8.2~22.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.8.2~22.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.8.2~22.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
