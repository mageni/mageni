# OpenVAS Vulnerability Test
# $Id: deb_3509.nasl 14279 2019-03-18 14:48:34Z cfischer $
# Auto-generated from advisory DSA 3509-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.703509");
  script_version("$Revision: 14279 $");
  script_cve_id("CVE-2016-0752", "CVE-2016-2097", "CVE-2016-2098");
  script_name("Debian Security Advisory DSA 3509-1 (rails - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-03-09 00:00:00 +0100 (Wed, 09 Mar 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2016/dsa-3509.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"rails on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 2:4.1.8-1+deb8u2.

For the testing distribution (stretch), these problems have been fixed
in version 2:4.2.5.2-1.

For the unstable distribution (sid), these problems have been fixed in
version 2:4.2.5.2-1.

We recommend that you upgrade your rails packages.");
  script_tag(name:"summary", value:"Two vulnerabilities have been discovered
in Rails, a web application framework written in Ruby. Both vulnerabilities affect
Action Pack, which handles the web requests for Rails.

CVE-2016-2097Crafted requests to Action View, one of the components of Action Pack,
might result in rendering files from arbitrary locations, including
files beyond the application's view directory. This vulnerability is
the result of an incomplete fix of
CVE-2016-0752
.
This bug was found by Jyoti Singh and Tobias Kraze from Makandra.

CVE-2016-2098
If a web applications does not properly sanitize user inputs, an
attacker might control the arguments of the render method in a
controller or a view, resulting in the possibility of executing
arbitrary ruby code.
This bug was found by Tobias Kraze from Makandra and joernchen of
Phenoelit.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"rails", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-actionmailer", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-actionpack", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-actionview", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activemodel", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activerecord", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activesupport", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activesupport-2.3", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-rails", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-railties", ver:"2:4.1.8-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"rails", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-actionmailer", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-actionpack", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-actionview", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activejob", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activemodel", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activerecord", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-activesupport", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-rails", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-railties", ver:"2:4.2.5.2-1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}