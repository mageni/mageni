# OpenVAS Vulnerability Test
# $Id: deb_2835.nasl 14302 2019-03-19 08:28:48Z cfischer $
# Auto-generated from advisory DSA 2835-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.702835");
  script_version("$Revision: 14302 $");
  script_cve_id("CVE-2013-7100");
  script_name("Debian Security Advisory DSA 2835-1 (asterisk - buffer overflow)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-05 00:00:00 +0100 (Sun, 05 Jan 2014)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2835.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");
  script_tag(name:"affected", value:"asterisk on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (squeeze), this problem has been fixed in
version 1:1.6.2.9-2+squeeze12.

For the stable distribution (wheezy), this problem has been fixed in
version 1:1.8.13.1~dfsg1-3+deb7u3.

For the testing distribution (jessie), this problem has been fixed in
version 1:11.7.0~dfsg-1.

For the unstable distribution (sid), this problem has been fixed in
version 1:11.7.0~dfsg-1.

We recommend that you upgrade your asterisk packages.");
  script_tag(name:"summary", value:"Jan Juergens discovered a buffer overflow in the parser for SMS messages
in Asterisk.

An additional change was backported, which is fully described AST-2013-007.html.
With the fix for AST-2013-007, a new configuration option was added in
order to allow the system adminitrator to disable the expansion of
dangerous
functions (such as SHELL()) from any interface which is not
the dialplan. In stable and oldstable this option is disabled by default.
To enable it add the following line to the section '[options]' in
/etc/asterisk/asterisk.conf (and restart asterisk)

live_dangerously = no");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.6.2.9-2+squeeze12", rls:"DEB6")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dahdi", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dbg", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mobile", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-modules", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mp3", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-mysql", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-ooh323", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail-imapstorage", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"asterisk-voicemail-odbcstorage", ver:"1:1.8.13.1~dfsg1-3+deb7u3", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}