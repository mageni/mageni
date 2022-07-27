###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1265.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1265-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.891265");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2013-1418", "CVE-2014-5351", "CVE-2014-5353", "CVE-2014-5355", "CVE-2016-3119", "CVE-2016-3120");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1265-1] krb5 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/01/msg00040.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"krb5 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.10.1+dfsg-5+deb7u9.

We recommend that you upgrade your krb5 packages.");
  script_tag(name:"summary", value:"Kerberos, a system for authenticating users and services on a network,
was affected by several vulnerabilities. The Common Vulnerabilities
and Exposures project identifies the following issues.

CVE-2013-1418
Kerberos allows remote attackers to cause a denial of service
(NULL pointer dereference and daemon crash) via a crafted request
when multiple realms are configured.

CVE-2014-5351
Kerberos sends old keys in a response to a -randkey -keepold
request, which allows remote authenticated users to forge tickets by
leveraging administrative access.

CVE-2014-5353
When the KDC uses LDAP, allows remote authenticated users to cause a
denial of service (daemon crash) via a successful LDAP query with no
results, as demonstrated by using an incorrect object type for a
password policy.

CVE-2014-5355
Kerberos expects that a krb5_read_message data field is represented
as a string ending with a '\0' character, which allows remote
attackers to (1) cause a denial of service (NULL pointer
dereference) via a zero-byte version string or (2) cause a denial of
service (out-of-bounds read) by omitting the '\0' character,

CVE-2016-3119
Kerberos allows remote authenticated users to cause a denial of
service (NULL pointer dereference and daemon crash) via a crafted
request to modify a principal.

CVE-2016-3120
Kerberos allows remote authenticated users to cause a denial of
service (NULL pointer dereference and daemon crash) via an S4U2Self
request.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit8", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit8", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-6", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.10.1+dfsg-5+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}