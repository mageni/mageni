###############################################################################
# OpenVAS Vulnerability Test
# $Id: alas-2014-437.nasl 6995 2017-08-23 11:52:03Z teissa$
#
# Amazon Linux security check
#
# Authors:
# Eero Volotinen <eero.volotinen@iki.fi>
#
# Copyright:
# Copyright (c) 2015 Eero Volotinen, http://ping-viini.org
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.120346");
  script_version("$Revision: 11703 $");
  script_tag(name:"creation_date", value:"2015-09-08 13:24:17 +0200 (Tue, 08 Sep 2015)");
  script_tag(name:"last_modification", value:"$Date: 2018-10-01 10:05:31 +0200 (Mon, 01 Oct 2018) $");
  script_name("Amazon Linux Local Check: ALAS-2014-437");
  script_tag(name:"insight", value:"crpyto/tls in Go 1.1 before 1.3.2, when SessionTicketsDisabled is enabled, allows man-in-the-middle attackers to spoof clients via unspecified vectors.");
  script_tag(name:"solution", value:"Run yum update golang to update your system.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://alas.aws.amazon.com/ALAS-2014-437.html");
  script_cve_id("CVE-2014-7189");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/amazon_linux", "ssh/login/release");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"Amazon Linux Local Security Checks");
  script_copyright("Eero Volotinen");
  script_family("Amazon Linux Local Security Checks");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "AMAZON")
{
if ((res = isrpmvuln(pkg:"golang-pkg-bin-linux", rpm:"golang-pkg-bin-linux~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-netbsd-amd64", rpm:"golang-pkg-netbsd-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-linux-amd64", rpm:"golang-pkg-linux-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-freebsd-amd64", rpm:"golang-pkg-freebsd-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-vim", rpm:"golang-vim~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-darwin-amd64", rpm:"golang-pkg-darwin-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-netbsd", rpm:"golang-pkg-netbsd~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-openbsd-amd64", rpm:"golang-pkg-openbsd-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-linux-arm", rpm:"golang-pkg-linux-arm~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-openbsd", rpm:"golang-pkg-openbsd~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-plan9-amd64", rpm:"golang-pkg-plan9-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-darwin", rpm:"golang-pkg-darwin~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-plan9", rpm:"golang-pkg-plan9~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-netbsd-arm", rpm:"golang-pkg-netbsd-arm~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-windows-amd64", rpm:"golang-pkg-windows-amd64~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"emacs-golang", rpm:"emacs-golang~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-freebsd-arm", rpm:"golang-pkg-freebsd-arm~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-linux", rpm:"golang-pkg-linux~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-freebsd", rpm:"golang-pkg-freebsd~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-pkg-windows", rpm:"golang-pkg-windows~386~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if ((res = isrpmvuln(pkg:"golang-src", rpm:"golang-src~1.3.3~1.7.amzn1", rls:"AMAZON")) != NULL) {
  security_message(data:res);
  exit(0);
}
if (__pkg_match) exit(99);
  exit(0);
}
