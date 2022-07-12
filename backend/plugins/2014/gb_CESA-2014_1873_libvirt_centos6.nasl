###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libvirt CESA-2014:1873 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882087");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-11-20 06:42:42 +0100 (Thu, 20 Nov 2014)");
  script_cve_id("CVE-2014-3633", "CVE-2014-3657", "CVE-2014-7823");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_name("CentOS Update for libvirt CESA-2014:1873 centos6");

  script_tag(name:"summary", value:"Check the version of libvirt");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libvirt library is a C API for managing
and interacting with the virtualization capabilities of Linux and other operating
systems. In addition, libvirt provides tools for remote management of
virtualized systems.

An out-of-bounds read flaw was found in the way libvirt's
qemuDomainGetBlockIoTune() function looked up the disk index in a
non-persistent (live) disk configuration while a persistent disk
configuration was being indexed. A remote attacker able to establish a
read-only connection to libvirtd could use this flaw to crash libvirtd or,
potentially, leak memory from the libvirtd process. (CVE-2014-3633)

A denial of service flaw was found in the way libvirt's
virConnectListAllDomains() function computed the number of used domains.
A remote attacker able to establish a read-only connection to libvirtd
could use this flaw to make any domain operations within libvirt
unresponsive. (CVE-2014-3657)

It was found that when the VIR_DOMAIN_XML_MIGRATABLE flag was used, the
QEMU driver implementation of the virDomainGetXMLDesc() function could
bypass the restrictions of the VIR_DOMAIN_XML_SECURE flag. A remote
attacker able to establish a read-only connection to libvirtd could use
this flaw to leak certain limited information from the domain XML data.
(CVE-2014-7823)

The CVE-2014-3633 issue was discovered by Luyao Huang of Red Hat.

This update also fixes the following bug:

When dumping migratable XML configuration of a domain, libvirt removes some
automatically added devices for compatibility with older libvirt releases.
If such XML is passed to libvirt as a domain XML that should be used during
migration, libvirt checks this XML for compatibility with the internally
stored configuration of the domain. However, prior to this update, these
checks failed because of devices that were missing (the same devices
libvirt removed). As a consequence, migration with user-supplied migratable
XML failed. Since this feature is used by OpenStack, migrating QEMU/KVM
domains with OpenStack always failed. With this update, before checking
domain configurations for compatibility, libvirt transforms both
user-supplied and internal configuration into a migratable form
(automatically added devices are removed) and checks those instead. Thus,
no matter whether the user-supplied configuration was generated as
migratable or not, libvirt does not err about missing devices, and
migration succeeds as expected. (BZ#1155564)

All libvirt users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, libvirtd will be restarted automatically.");
  script_tag(name:"affected", value:"libvirt on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-November/020771.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"libvirt", rpm:"libvirt~0.10.2~46.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-client", rpm:"libvirt-client~0.10.2~46.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-devel", rpm:"libvirt-devel~0.10.2~46.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-python", rpm:"libvirt-python~0.10.2~46.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libvirt-lock-sanlock", rpm:"libvirt-lock-sanlock~0.10.2~46.el6_6.2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
