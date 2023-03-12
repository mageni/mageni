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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2031");
  script_cve_id("CVE-2010-0629");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2031)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2031");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2031");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'krb5' package(s) announced via the DSA-2031 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sol Jerome discovered that kadmind service in krb5, a system for authenticating users and services on a network, allows remote authenticated users to cause a denial of service (daemon crash) via a request from a kadmin client that sends an invalid API version number.

For the stable distribution (lenny), this problem has been fixed in version 1.6.dfsg.4~beta1-5lenny3.

The testing distribution (squeeze), and the unstable distribution (sid) are not affected by this issue.

We recommend that you upgrade your krb5 package.");

  script_tag(name:"affected", value:"'krb5' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-clients", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-doc", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"krb5-user", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkadm55", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.4~beta1-5lenny3", rls:"DEB5"))) {
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
