# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.57.1");
  script_cve_id("CVE-2004-1235", "CVE-2004-1337");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-57-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-57-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-57-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-source-2.6.8.1' package(s) announced via the USN-57-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Starzetz discovered a race condition in the ELF library and a.out
binary format loaders, which can be locally exploited in several
different ways to gain root privileges. (CAN-2004-1235)

Liang Bin found a design flaw in the capability module. After this
module was loaded on demand in a running system, all unprivileged user
space processes got all kernel capabilities (thus essentially root
privileges). This is mitigated by the fact that the capability module
is loaded very early in the boot process of a standard Ubuntu system,
when no unprivileged user processes are yet running. (CAN-2004-1337)

Finally, this update fixes a memory leak in the ip_conntrack_ftp
iptables module. However, it is believed that this is not exploitable.");

  script_tag(name:"affected", value:"'linux-source-2.6.8.1' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.8.1", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-386", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-686-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-686", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-generic", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-k8-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-k8", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-amd64-xeon", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-k7-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-k7", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power3-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power3", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power4-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-power4", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-powerpc-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4-powerpc", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.8.1-4", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-386", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-686-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-686", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-generic", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-k8-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-k8", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-amd64-xeon", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-k7-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-k7", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power3-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power3", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power4-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-power4", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-powerpc-smp", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.8.1-4-powerpc", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.8.1", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.8.1", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tree-2.6.8.1", ver:"2.6.8.1-16.8", rls:"UBUNTU4.10"))) {
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
