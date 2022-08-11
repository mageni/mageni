###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libvirt RHSA-2014:0560-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871168");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-06-02 17:44:23 +0530 (Mon, 02 Jun 2014)");
  script_cve_id("CVE-2014-0179");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_name("RedHat Update for libvirt RHSA-2014:0560-01");


  script_tag(name:"affected", value:"libvirt on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing and interacting with the
virtualization capabilities of Linux and other operating systems. In
addition, libvirt provides tools for remote management of virtualized
systems.

It was found that libvirt passes the XML_PARSE_NOENT flag when parsing XML
documents using the libxml2 library, in which case all XML entities in the
parsed documents are expanded. A user able to force libvirtd to parse an
XML document with an entity pointing to a special file that blocks on read
access could use this flaw to cause libvirtd to hang indefinitely,
resulting in a denial of service on the system. (CVE-2014-0179)

Red Hat would like to thank the upstream Libvirt project for reporting this
issue. Upstream acknowledges Daniel P. Berrange and Richard Jones as the
original reporters.

This update also fixes the following bugs:

  * When hot unplugging a virtual CPU (vCPU), libvirt kept a pointer to
already freed memory if the vCPU was pinned to a host CPU. Consequently,
when reading the CPU pinning information, libvirt terminated unexpectedly
due to an attempt to access this memory. This update ensures that libvirt
releases the pointer to the previously allocated memory when a vCPU is
being hot unplugged, and it no longer crashes in this situation.
(BZ#1091206)

  * Previously, libvirt passed an incorrect argument to the 'tc' command when
setting quality of service (QoS) on a network interface controller (NIC).
As a consequence, QoS was applied only to IP traffic. With this update,
libvirt constructs the 'tc' command correctly so that QoS is applied to all
traffic as expected. (BZ#1096806)

  * When using the sanlock daemon for managing access to shared storage,
libvirt expected all QEMU domains to be registered with sanlock. However,
if a QEMU domain was started prior to enabling sanlock, the domain was not
registered with sanlock. Consequently, migration of a virtual machine (VM)
from such a QEMU domain failed with a libvirt error. With this update,
libvirt verifies whether a QEMU domain process is registered with sanlock
before it starts working with the domain, ensuring that migration of
virtual machines works as expected. (BZ#1097227)

All libvirt users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, libvirtd will be restarted automatically.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-May/msg00034.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~29.el6_5.8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~29.el6_5.8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-debuginfo", rpm:"libvirt-debuginfo~0.10.2~29.el6_5.8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~29.el6_5.8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~29.el6_5.8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
