# OpenVAS Vulnerability Test
# Auto-generated from advisory DSA 3828-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.703828");
  script_version("2021-11-23T15:20:34+0000");
  script_cve_id("CVE-2017-2669");
  script_name("Debian Security Advisory DSA 3828-1 (dovecot - security update)");
  script_tag(name:"last_modification", value:"2021-11-24 11:00:45 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2017-04-10 00:00:00 +0200 (Mon, 10 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:27:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3828.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"dovecot on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie), this problem has been fixed in
version 1:2.2.13-12~deb8u2.

We recommend that you upgrade your dovecot packages.");
  script_tag(name:"summary", value:"It was discovered that the Dovecot email server is vulnerable to a
denial of service attack. When the dict
passdb and userdb are used
for user authentication, the username sent by the IMAP/POP3 client is
sent through var_expand() to perform %variable expansion. Sending
specially crafted %variable fields could result in excessive memory
usage causing the process to crash (and restart).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"dovecot-core", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-dbg", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-dev", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-gssapi", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-imapd", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-ldap", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-lmtpd", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-lucene", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-managesieved", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-mysql", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-pgsql", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-pop3d", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-sieve", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-solr", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"dovecot-sqlite", ver:"1:2.2.13-12~deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}