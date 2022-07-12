# OpenVAS Vulnerability Test
# $Id: deb_3038.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 3038-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703038");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2014-0179", "CVE-2014-3633");
  script_name("Debian Security Advisory DSA 3038-1 (libvirt - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-01 16:57:50 +0530 (Wed, 01 Oct 2014)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-3038.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"libvirt on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (wheezy), these problems have been fixed in
version 0.9.12.3-1+deb7u1.

For the unstable distribution (sid), these problems have been fixed in
version 1.2.8-2.

We recommend that you upgrade your libvirt packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in Libvirt, a virtualisation
abstraction library. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2014-0179
Richard Jones and Daniel P. Berrange found that libvirt passes the
XML_PARSE_NOENT flag when parsing XML documents using the libxml2
library, in which case all XML entities in the parsed documents are
expanded. A user able to force libvirtd to parse an XML document
with an entity pointing to a special file that blocks on read access
could use this flaw to cause libvirtd to hang indefinitely,
resulting in a denial of service on the system.

CVE-2014-3633
Luyao Huang of Red Hat found that the qemu implementation of
virDomainGetBlockIoTune computed an index into the array of disks
for the live definition, then used it as the index into the array of
disks for the persistent definition, which could result into an
out-of-bounds read access in qemuDomainGetBlockIoTune().

A remote attacker able to establish a read-only connection to
libvirtd could use this flaw to crash libvirtd or, potentially, leak
memory from the libvirtd process.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libvirt-bin", ver:"0.9.12.3-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-dev", ver:"0.9.12.3-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt-doc", ver:"0.9.12.3-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt0", ver:"0.9.12.3-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libvirt0-dbg", ver:"0.9.12.3-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-libvirt", ver:"0.9.12.3-1+deb7u1", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}