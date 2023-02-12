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
  script_oid("1.3.6.1.4.1.25623.1.0.893287");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2020-16093", "CVE-2022-37186");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-30 09:58:56 +0000 (Mon, 30 Jan 2023)");
  script_name("Debian LTS: Security Advisory for lemonldap-ng (DLA-3287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3287-1");
  script_xref(name:"Advisory-ID", value:"DLA-3287-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lemonldap-ng'
  package(s) announced via the DLA-3287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities were found in lemonldap-ng, an OpenID-Connect, CAS
and SAML compatible Web-SSO system, that could result in information
disclosure or impersonation.

CVE-2020-16093

Maxime Besson discovered that LemonLDAP::NG before 2.0.9 did not
check validity of the X.509 certificate by default when connecting
to remote LDAP backends, because the default configuration of the
Net::LDAPS module for Perl is used.

This update changes the default behavior to require X.509 validation
against the distribution bundle /etc/ssl/certs/ca-certificates.crt.
Previous behavior can reverted by running
`/usr/share/lemonldap-ng/bin/lemonldap-ng-cli set ldapVerify none`.

If a session backend is set to Apache::Session::LDAP or
Apache::Session::Browsable::LDAP, then the complete fix involves
upgrading the corresponding Apache::Session module
(libapache-session-ldap-perl resp. libapache-session-browseable-perl)
to 0.4-1+deb10u1 (or '>='0.5) resp. 1.3.0-1+deb10u1 (or '>='1.3.8). See
related advisories DLA-3284-1 and DLA-3285-1 for details.

CVE-2022-37186

Mickael Bride discovered that under certain conditions the session
remained valid on handlers after being destroyed on portal.");

  script_tag(name:"affected", value:"'lemonldap-ng' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.0.2+ds-7+deb10u8.

We recommend that you upgrade your lemonldap-ng packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-doc", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-fastcgi-server", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-handler", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"lemonldap-ng-uwsgi-app", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-common-perl", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-handler-perl", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-manager-perl", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblemonldap-ng-portal-perl", ver:"2.0.2+ds-7+deb10u8", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
