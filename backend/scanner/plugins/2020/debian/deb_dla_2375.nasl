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
  script_oid("1.3.6.1.4.1.25623.1.0.892375");
  script_version("2020-09-21T08:50:33+0000");
  script_cve_id("CVE-2019-20917", "CVE-2020-25269");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-09-21 10:25:22 +0000 (Mon, 21 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-21 03:00:07 +0000 (Mon, 21 Sep 2020)");
  script_name("Debian LTS: Security Advisory for inspircd (DLA-2375-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2375-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'inspircd'
  package(s) announced via the DLA-2375-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues were discovered in the modules of the InspIRCd IRC
daemon, which could result in denial of service.

CVE-2019-20917

mysql module before v3.3.0 contains a null pointer dereference when
built against mariadb-connector-c. When combined with the sqlauth or
sqloper modules this vulnerability can be used to remotely crash an
InspIRCd server by any user able to connect to a server.

CVE-2020-25269

The pgsql module contains a use after free vulnerability. When combined
with the sqlauth or sqloper modules this vulnerability can be used to
remotely crash an InspIRCd server by any user able to connect to a
server.");

  script_tag(name:"affected", value:"'inspircd' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.0.23-2+deb9u1.

We recommend that you upgrade your inspircd packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"inspircd", ver:"2.0.23-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"inspircd-dbg", ver:"2.0.23-2+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"inspircd-dev", ver:"2.0.23-2+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
