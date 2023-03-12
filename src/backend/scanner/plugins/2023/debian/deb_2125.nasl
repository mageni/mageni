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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2125");
  script_cve_id("CVE-2010-3864");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2125)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2125");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2125");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-2125 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw has been found in the OpenSSL TLS server extension code parsing which on affected servers can be exploited in a buffer overrun attack. This allows an attacker to cause an application crash or potentially to execute arbitrary code.

However, not all OpenSSL based SSL/TLS servers are vulnerable: a server is vulnerable if it is multi-threaded and uses OpenSSL's internal caching mechanism. In particular the Apache HTTP server (which never uses OpenSSL internal caching) and Stunnel (which includes its own workaround) are NOT affected.

This upgrade fixes this issue. After the upgrade, any services using the openssl libraries need to be restarted. The checkrestart script from the debian-goodies package or lsof can help to find out which services need to be restarted.

A note to users of the tor packages from the Debian backports or Debian volatile: this openssl update causes problems with some versions of tor. You need to update to tor 0.2.1.26-4~bpo50+1 or 0.2.1.26-1~lennyvolatile2, respectively. The tor package version 0.2.0.35-1~lenny2 from Debian stable is not affected by these problems.

For the stable distribution (lenny), the problem has been fixed in openssl version 0.9.8g-15+lenny9.

For the testing distribution (squeeze) and the unstable distribution (sid), this problem has been fixed in version 0.9.8o-3.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 5.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto0.9.8-udeb", ver:"0.9.8g-15+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"0.9.8g-15+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8-dbg", ver:"0.9.8g-15+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl0.9.8", ver:"0.9.8g-15+lenny9", rls:"DEB5"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"0.9.8g-15+lenny9", rls:"DEB5"))) {
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
