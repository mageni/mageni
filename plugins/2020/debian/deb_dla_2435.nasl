# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892435");
  script_version("2020-11-07T04:00:10+0000");
  script_cve_id("CVE-2020-9497", "CVE-2020-9498");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-11-09 11:47:04 +0000 (Mon, 09 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-07 04:00:10 +0000 (Sat, 07 Nov 2020)");
  script_name("Debian LTS: Security Advisory for guacamole-server (DLA-2435-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2435-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/964195");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'guacamole-server'
  package(s) announced via the DLA-2435-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The server component of Apache Guacamole, a remote desktop gateway,
did not properly validate data received from RDP servers. This could
result
in information disclosure or even the execution of arbitrary code.

CVE-2020-9497

Apache Guacamole does not properly validate data received from RDP
servers via static virtual channels. If a user connects to a
malicious or compromised RDP server, specially-crafted PDUs could
result in disclosure of information within the memory of the guacd
process handling the connection.

CVE-2020-9498

Apache Guacamole may mishandle pointers involved in processing data
received via RDP static virtual channels. If a user connects to a
malicious or compromised RDP server, a series of specially-crafted
PDUs could result in memory corruption, possibly allowing arbitrary
code to be executed with the privileges of the running guacd
process.");

  script_tag(name:"affected", value:"'guacamole-server' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
0.9.9-2+deb9u1.

We recommend that you upgrade your guacamole-server packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"guacd", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libguac-client-rdp0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libguac-client-ssh0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libguac-client-telnet0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libguac-client-vnc0", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libguac-dev", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libguac11", ver:"0.9.9-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
