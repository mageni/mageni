###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1480.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1480-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891480");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2016-2337", "CVE-2018-1000073", "CVE-2018-1000074");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1480-1] ruby2.1 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-09-03 00:00:00 +0200 (Mon, 03 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00028.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"ruby2.1 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u5.

We recommend that you upgrade your ruby2.1 packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in Ruby 2.1.

CVE-2016-2337

Type confusion exists in _cancel_eval Ruby's TclTkIp class
method. Attacker passing different type of object than String as
'retval' argument can cause arbitrary code execution.

CVE-2018-1000073

RubyGems contains a Directory Traversal vulnerability in
install_location function of package.rb that can result in path
traversal when writing to a symlinked basedir outside of the root.

CVE-2018-1000074

RubyGems contains a Deserialization of Untrusted Data
vulnerability in owner command that can result in code
execution. This attack appear to be exploitable via victim must
run the `gem owner` command on a gem with a specially crafted YAML
file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libruby2.1", ver:"2.1.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.1", ver:"2.1.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.1-dev", ver:"2.1.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.1-doc", ver:"2.1.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby2.1-tcltk", ver:"2.1.5-2+deb8u5", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}