###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1615.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1615-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891615");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2013-7108", "CVE-2013-7205", "CVE-2014-1878", "CVE-2016-9566", "CVE-2018-18245");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1615-1] nagios3 security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-12-28 00:00:00 +0100 (Fri, 28 Dec 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/12/msg00014.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"nagios3 on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.5.1.dfsg-2+deb8u1.

We recommend that you upgrade your nagios3 packages.");
  script_tag(name:"summary", value:"Several issues were corrected in nagios3, a monitoring and management
system for hosts, services and networks.

CVE-2018-18245

Maximilian Boehner of usd AG found a cross-site scripting (XSS)
vulnerability in Nagios Core. This vulnerability allows attackers
to place malicious JavaScript code into the web frontend through
manipulation of plugin output. In order to do this the attacker
needs to be able to manipulate the output returned by nagios
checks, e.g. by replacing a plugin on one of the monitored
endpoints. Execution of the payload then requires that an
authenticated user creates an alert summary report which contains
the corresponding output.

CVE-2016-9566

It was discovered that local users with access to an account in
the nagios group are able to gain root privileges via a symlink
attack on the debug log file.

CVE-2014-1878

An issue was corrected that allowed remote attackers to cause a
stack-based buffer overflow and subsequently a denial of service
(segmentation fault) via a long message to cmd.cgi.

CVE-2013-7205, CVE-2013-7108

A flaw was corrected in Nagios that could be exploited to cause a
denial-of-service. This vulnerability is induced due to an
off-by-one error within the process_cgivars() function, which can
be exploited to cause an out-of-bounds read by sending a
specially-crafted key value to the Nagios web UI.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"nagios3", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nagios3-cgi", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nagios3-common", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nagios3-core", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nagios3-dbg", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"nagios3-doc", ver:"3.5.1.dfsg-2+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}