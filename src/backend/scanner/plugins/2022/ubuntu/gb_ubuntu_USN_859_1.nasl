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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2009.859.1");
  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2009-3885");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-859-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(8\.10|9\.04|9\.10)");

  script_xref(name:"Advisory-ID", value:"USN-859-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-859-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-859-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Kaminsky discovered that SSL certificates signed with MD2 could be
spoofed given enough time. As a result, an attacker could potentially
create a malicious trusted certificate to impersonate another site. This
update handles this issue by completely disabling MD2 for certificate
validation in OpenJDK. (CVE-2009-2409)

It was discovered that ICC profiles could be identified with
'..' pathnames. If a user were tricked into running a specially
crafted applet, a remote attacker could gain information about a local
system. (CVE-2009-3728)

Peter Vreugdenhil discovered multiple flaws in the processing of graphics
in the AWT library. If a user were tricked into running a specially
crafted applet, a remote attacker could crash the application or run
arbitrary code with user privileges. (CVE-2009-3869, CVE-2009-3871)

Multiple flaws were discovered in JPEG and BMP image handling. If a user
were tricked into loading a specially crafted image, a remote attacker
could crash the application or run arbitrary code with user privileges.
(CVE-2009-3873, CVE-2009-3874, CVE-2009-3885)

Coda Hale discovered that HMAC-based signatures were not correctly
validated. Remote attackers could bypass certain forms of authentication,
granting unexpected access. (CVE-2009-3875)

Multiple flaws were discovered in ASN.1 parsing. A remote attacker
could send a specially crafted HTTP stream that would exhaust system
memory and lead to a denial of service. (CVE-2009-3876, CVE-2009-3877)

It was discovered that the graphics configuration subsystem did
not correctly handle arrays. If a user were tricked into running
a specially crafted applet, a remote attacker could exploit this
to crash the application or execute arbitrary code with user
privileges. (CVE-2009-3879)

It was discovered that loggers and Swing did not correctly handle
certain sensitive objects. If a user were tricked into running a
specially crafted applet, private information could be leaked to a remote
attacker, leading to a loss of privacy. (CVE-2009-3880, CVE-2009-3882,
CVE-2009-3883)

It was discovered that the ClassLoader did not correctly handle certain
options. If a user were tricked into running a specially crafted
applet, a remote attacker could execute arbitrary code with user
privileges. (CVE-2009-3881)

It was discovered that time zone file loading could be used to determine
the existence of files on the local system. If a user were tricked into
running a specially crafted applet, private information could be leaked
to a remote attacker, leading to a loss of privacy. (CVE-2009-3884)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

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

if(release == "UBUNTU8.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b12-0ubuntu6.6", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b12-0ubuntu6.6", rls:"UBUNTU8.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.04") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b14-1.4.1-0ubuntu12", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b14-1.4.1-0ubuntu12", rls:"UBUNTU9.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU9.10") {

  if(!isnull(res = isdpkgvuln(pkg:"icedtea6-plugin", ver:"6b16-1.6.1-3ubuntu1", rls:"UBUNTU9.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b16-1.6.1-3ubuntu1", rls:"UBUNTU9.10"))) {
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
