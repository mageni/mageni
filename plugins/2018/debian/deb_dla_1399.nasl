###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1399.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1399-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891399");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2015-7519", "CVE-2018-12029");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1399-1] ruby-passenger security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-10 00:00:00 +0200 (Tue, 10 Jul 2018)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/06/msg00007.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"ruby-passenger on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
4.0.53-1+deb8u1.

We recommend that you upgrade your ruby-passenger packages.");
  script_tag(name:"summary", value:"Two flaws were discovered in ruby-passenger for Ruby Rails and Rack
support that allowed attackers to spoof HTTP headers or exploit a race
condition which made privilege escalation under certain conditions
possible.

CVE-2015-7519
Remote attackers could spoof headers passed to applications by using
an underscore character instead of a dash character in an HTTP
header as demonstrated by an X_User header.

CVE-2018-12029
A vulnerability was discovered by the Pulse Security team. It was
exploitable only when running a non-standard
passenger_instance_registry_dir, via a race condition where after a
file was created, there was a window in which it could be replaced
with a symlink before it was chowned via the path and not the file
descriptor. If the symlink target was to a file which would be
executed by root such as root's crontab file, then privilege
escalation was possible. This is now mitigated by using fchown().");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-passenger", ver:"4.0.53-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-passenger", ver:"4.0.53-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"ruby-passenger-doc", ver:"4.0.53-1+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}