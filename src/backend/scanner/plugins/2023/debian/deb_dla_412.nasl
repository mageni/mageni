# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.412");
  script_cve_id("CVE-2015-7566", "CVE-2015-8767", "CVE-2015-8785", "CVE-2016-0723", "CVE-2016-2069");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-412)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-412");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-412");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DLA-412 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the CVEs described below.

CVE-2015-7566

Ralf Spenneberg of OpenSource Security reported that the visor driver crashes when a specially crafted USB device without bulk-out endpoint is detected.

CVE-2015-8767

An SCTP denial-of-service was discovered which can be triggered by a local attacker during a heartbeat timeout event after the 4-way handshake.

CVE-2015-8785

It was discovered that local users permitted to write to a file on a FUSE filesystem could cause a denial of service (unkillable loop in the kernel).

CVE-2016-0723

A use-after-free vulnerability was discovered in the TIOCGETD ioctl. A local attacker could use this flaw for denial-of-service.

CVE-2016-2069

Andy Lutomirski discovered a race condition in flushing of the TLB when switching tasks. On an SMP system this could possibly lead to a crash, information leak or privilege escalation.

For the oldoldstable distribution (squeeze), these problems have been fixed in version 2.6.32-48squeeze19. Additionally, this version includes upstream stable update 2.6.32.70. This is the final update to the linux-2.6 package for squeeze.

For the oldstable distribution (wheezy), these problems will be fixed soon.

For the stable distribution (jessie), CVE-2015-7566, CVE-2015-8767 and CVE-2016-0723 were fixed in linux version 3.16.7-ckt20-1+deb8u3 and the remaining problems will be fixed soon.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux-free", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-base", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.32", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-486", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-i386", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-openvz", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-vserver", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-xen", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-486", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64-dbg", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.32", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.32", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.32", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.32-5", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tools-2.6.32", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-686", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze19", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
