###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4130.nasl 14275 2019-03-18 14:39:45Z cfischer $
#
# Auto-generated from advisory DSA 4130-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704130");
  script_version("$Revision: 14275 $");
  script_cve_id("CVE-2017-14461", "CVE-2017-15130", "CVE-2017-15132");
  script_name("Debian Security Advisory DSA 4130-1 (dovecot - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-02 00:00:00 +0100 (Fri, 02 Mar 2018)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4130.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|8)");
  script_tag(name:"affected", value:"dovecot on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), these problems have been fixed
in version 1:2.2.13-12~deb8u4.

For the stable distribution (stretch), these problems have been fixed in
version 1:2.2.27-3+deb9u2.

We recommend that you upgrade your dovecot packages.

For the detailed security status of dovecot please refer to its security
tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dovecot");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the Dovecot email
server. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2017-14461Aleksandar Nikolic of Cisco Talos and flxflndy
discovered that
Dovecot does not properly parse invalid email addresses, which may
cause a crash or leak memory contents to an attacker.

CVE-2017-15130It was discovered that TLS SNI config lookups may lead to excessive
memory usage, causing imap-login/pop3-login VSZ limit to be reached
and the process restarted, resulting in a denial of service. Only
Dovecot configurations containing local_name { } or local { }

configuration blocks are affected.

CVE-2017-15132
It was discovered that Dovecot contains a memory leak flaw in the
login process on aborted SASL authentication.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.27-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.13-12~deb8u4", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}