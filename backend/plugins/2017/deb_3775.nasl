# OpenVAS Vulnerability Test
# $Id: deb_3775.nasl 14280 2019-03-18 14:50:45Z cfischer $
# Auto-generated from advisory DSA 3775-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703775");
  script_version("$Revision: 14280 $");
  script_cve_id("CVE-2016-7922", "CVE-2016-7923", "CVE-2016-7924", "CVE-2016-7925",
                  "CVE-2016-7926", "CVE-2016-7927", "CVE-2016-7928", "CVE-2016-7929",
                  "CVE-2016-7930", "CVE-2016-7931", "CVE-2016-7932", "CVE-2016-7933",
                  "CVE-2016-7934", "CVE-2016-7935", "CVE-2016-7936", "CVE-2016-7937",
                  "CVE-2016-7938", "CVE-2016-7939", "CVE-2016-7940", "CVE-2016-7973",
                  "CVE-2016-7974", "CVE-2016-7975", "CVE-2016-7983", "CVE-2016-7984",
                  "CVE-2016-7985", "CVE-2016-7986", "CVE-2016-7992", "CVE-2016-7993",
                  "CVE-2016-8574", "CVE-2016-8575", "CVE-2017-5202", "CVE-2017-5203",
                  "CVE-2017-5204", "CVE-2017-5205", "CVE-2017-5341", "CVE-2017-5342",
                  "CVE-2017-5482", "CVE-2017-5483", "CVE-2017-5484", "CVE-2017-5485",
                  "CVE-2017-5486");
  script_name("Debian Security Advisory DSA 3775-1 (tcpdump - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:50:45 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-01-29 00:00:00 +0100 (Sun, 29 Jan 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2017/dsa-3775.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"tcpdump on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (jessie),
these problems have been fixed in version 4.9.0-1~deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 4.9.0-1.

For the unstable distribution (sid), these problems have been fixed in
version 4.9.0-1.

We recommend that you upgrade your tcpdump packages.");
  script_tag(name:"summary", value:"Multiple vulnerabilities have been
discovered in tcpdump, a command-line network traffic analyzer. These
vulnerabilities might result in denial of service or the execution of arbitrary
code.");
  script_tag(name:"vuldetect", value:"This check tests the installed software
version using the apt package manager.");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"tcpdump", ver:"4.9.0-1~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"tcpdump", ver:"4.9.0-1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}