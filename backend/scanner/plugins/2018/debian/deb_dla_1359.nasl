###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1359.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1359-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891359");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2017-17742", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1359-1] ruby1.8 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-04-25 00:00:00 +0200 (Wed, 25 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/04/msg00024.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"ruby1.8 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.8.7.358-7.1+deb7u6.

We recommend that you upgrade your ruby1.8 packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities were found in the interpreter for the Ruby
language. The Common Vulnerabilities and Exposures project identifies the
following issues:

CVE-2017-17742

Aaron Patterson reported that WEBrick bundled with Ruby was vulnerable to
an HTTP response splitting vulnerability. It was possible for an attacker
to inject fake HTTP responses if a script accepted an external input and
output it without modifications.

CVE-2018-6914

ooooooo_q discovered a directory traversal vulnerability in the
Dir.mktmpdir method in the tmpdir library. It made it possible for
attackers to create arbitrary directories or files via a .. (dot dot) in
the prefix argument.

CVE-2018-8777

Eric Wong reported an out-of-memory DoS vulnerability related to a large
request in WEBrick bundled with Ruby.

CVE-2018-8778

aerodudrizzt found a buffer under-read vulnerability in the Ruby
String#unpack method. If a big number was passed with the specifier @,
the number was treated as a negative value, and an out-of-buffer read
occurred. Attackers could read data on heaps if an script accepts an
external input as the argument of String#unpack.

CVE-2018-8779

ooooooo_q reported that the UNIXServer.open and UNIXSocket.open
methods of the socket library bundled with Ruby did not check for NUL
bytes in the path argument. The lack of check made the methods
vulnerable to unintentional socket creation and unintentional socket
access.

CVE-2018-8780

ooooooo_q discovered an unintentional directory traversal in
some methods in Dir, by the lack of checking for NUL bytes in their
parameter.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libruby1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libruby1.8-dbg", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libtcltk-ruby1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ri1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby1.8", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby1.8-dev", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby1.8-examples", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby1.8-full", ver:"1.8.7.358-7.1+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}