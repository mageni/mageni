# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892816");
  script_version("2021-11-18T02:00:11+0000");
  script_cve_id("CVE-2021-32739", "CVE-2021-32743", "CVE-2021-37698");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-11-18 02:00:11 +0000 (Thu, 18 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-18 02:00:11 +0000 (Thu, 18 Nov 2021)");
  script_name("Debian LTS: Security Advisory for icinga2 (DLA-2816-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2816-1");
  script_xref(name:"Advisory-ID", value:"DLA-2816-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/991494");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icinga2'
  package(s) announced via the DLA-2816-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Icinga 2, a general-purpose
monitoring application. An attacker could retrieve sensitive
information such as service passwords and ticket salt by querying the
web API, or by intercepting unsufficiently checked encrypted
connections.

CVE-2021-32739

A vulnerability exists that may allow privilege escalation for
authenticated API users. With a read-ony user's credentials, an
attacker can view most attributes of all config objects including
`ticket_salt` of `ApiListener`. This salt is enough to compute a
ticket for every possible common name (CN). A ticket, the master
node's certificate, and a self-signed certificate are enough to
successfully request the desired certificate from Icinga. That
certificate may in turn be used to steal an endpoint or API user's
identity. See also complementary manual procedures:

CVE-2021-32743

Some of the Icinga 2 features that require credentials for
external services expose those credentials through the API to
authenticated API users with read permissions for the
corresponding object types. IdoMysqlConnection and
IdoPgsqlConnection exposes the password of the user used to
connect to the database. An attacker who obtains these credentials
can impersonate Icinga to these services and add, modify and
delete information there. If credentials with more permissions are
in use, this increases the impact accordingly.

CVE-2021-37698

InfluxdbWriter and Influxdb2Writer do not verify the server's
certificate despite a certificate authority being
specified. Icinga 2 instances which connect to any of the
mentioned time series databases (TSDBs) using TLS over a spoofable
infrastructure should immediately upgrade. Such instances should
also change the credentials (if any) used by the TSDB writer
feature to authenticate against the TSDB.");

  script_tag(name:"affected", value:"'icinga2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.6.0-2+deb9u2.

We recommend that you upgrade your icinga2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"icinga2", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-bin", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-classicui", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-common", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-dbg", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-doc", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-ido-mysql", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-ido-pgsql", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"icinga2-studio", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libicinga2", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"vim-icinga2", ver:"2.6.0-2+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
