# OpenVAS Vulnerability Test
# $Id: deb_3388.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3388-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703388");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2014-9750", "CVE-2014-9751", "CVE-2015-3405", "CVE-2015-5146",
                  "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-5219", "CVE-2015-5300",
                  "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7701", "CVE-2015-7702",
                  "CVE-2015-7703", "CVE-2015-7704", "CVE-2015-7850", "CVE-2015-7852",
                  "CVE-2015-7855", "CVE-2015-7871");
  script_name("Debian Security Advisory DSA 3388-1 (ntp - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-05-06 15:29:25 +0530 (Fri, 06 May 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3388.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9|7)");
  script_tag(name:"affected", value:"ntp on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1:4.2.6.p5+dfsg-2+deb7u6.

For the stable distribution (jessie), these problems have been fixed in
version 1:4.2.6.p5+dfsg-7+deb8u1.

For the testing distribution (stretch), these problems have been fixed
in version 1:4.2.8p4+dfsg-3.

For the unstable distribution (sid), these problems have been fixed in
version 1:4.2.8p4+dfsg-3.

We recommend that you upgrade your ntp packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in the Network Time Protocol daemon and utility programs:

CVE-2015-5146
A flaw was found in the way ntpd processed certain remote
configuration packets. An attacker could use a specially crafted
package to cause ntpd to crash if:

ntpd enabled remote configurationThe attacker had the knowledge of the configuration
password...The attacker had access to a computer entrusted to perform remote
configuration
Note that remote configuration is disabled by default in NTP.

CVE-2015-5194
It was found that ntpd could crash due to an uninitialized
variable when processing malformed logconfig configuration
commands.

Description truncated. Please see the references for more information.");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-7+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.8p4+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.8p4+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.8p4+dfsg-3", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntp-doc", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ntpdate", ver:"1:4.2.6.p5+dfsg-2+deb7u6", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}