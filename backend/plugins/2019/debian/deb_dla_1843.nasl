# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891843");
  script_version("2019-07-04T02:00:08+0000");
  script_cve_id("CVE-2019-10162", "CVE-2019-10163");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-04 02:00:08 +0000 (Thu, 04 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-04 02:00:08 +0000 (Thu, 04 Jul 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1843-1] pdns security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00002.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1843-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns'
  package(s) announced via the DSA-1843-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in pdns, an authoritative DNS
server which may result in denial of service via malformed zone records
and excessive NOTIFY packets in a master/slave setup.

CVE-2019-10162

An issue has been found in PowerDNS Authoritative Server allowing
an authorized user to cause the server to exit by inserting a
crafted record in a MASTER type zone under their control. The issue
is due to the fact that the Authoritative Server will exit when it
runs into a parsing error while looking up the NS/A/AAAA records it
is about to use for an outgoing notify.

CVE-2019-10163

An issue has been found in PowerDNS Authoritative Server allowing
a remote, authorized master server to cause a high CPU load or even
prevent any further updates to any slave zone by sending a large
number of NOTIFY messages. Note that only servers configured as
slaves are affected by this issue.");

  script_tag(name:"affected", value:"'pdns' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.4.1-4+deb8u10.

We recommend that you upgrade your pdns packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-geo", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-ldap", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-lmdb", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-lua", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-mydns", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-mysql", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-pgsql", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-pipe", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-remote", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-backend-sqlite3", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-server", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"pdns-server-dbg", ver:"3.4.1-4+deb8u10", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);