###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4031.nasl 14284 2019-03-18 15:02:15Z cfischer $
#
# Auto-generated from advisory DSA 4031-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.704031");
  script_version("$Revision: 14284 $");
  script_cve_id("CVE-2017-0898", "CVE-2017-0903", "CVE-2017-10784", "CVE-2017-14033");
  script_name("Debian Security Advisory DSA 4031-1 (ruby2.3 - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:02:15 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-11 00:00:00 +0100 (Sat, 11 Nov 2017)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4031.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"ruby2.3 on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 2.3.3-1+deb9u2.

We recommend that you upgrade your ruby2.3 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the interpreter for the
Ruby language. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2017-0898
aerodudrizzt reported a buffer underrun vulnerability in the sprintf
method of the Kernel module resulting in heap memory corruption or
information disclosure from the heap.

CVE-2017-0903
Max Justicz reported that RubyGems is prone to an unsafe object
deserialization vulnerability. When parsed by an application which
processes gems, a specially crafted YAML formatted gem specification
can lead to remote code execution.

CVE-2017-10784
Yusuke Endoh discovered an escape sequence injection vulnerability
in the Basic authentication of WEBrick. An attacker can take
advantage of this flaw to inject malicious escape sequences to the
WEBrick log and potentially execute control characters on the
victim's terminal emulator when reading logs.

CVE-2017-14033
asac reported a buffer underrun vulnerability in the OpenSSL
extension. A remote attacker can take advantage of this flaw to
cause the Ruby interpreter to crash leading to a denial of service.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.3-dev", ver:"2.3.3-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.3-doc", ver:"2.3.3-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.3-tcltk", ver:"2.3.3-1+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}