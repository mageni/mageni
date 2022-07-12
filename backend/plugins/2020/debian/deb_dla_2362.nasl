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
  script_oid("1.3.6.1.4.1.25623.1.0.892362");
  script_version("2020-09-03T06:31:30+0000");
  script_cve_id("CVE-2020-11984");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-03 09:52:01 +0000 (Thu, 03 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-03 03:00:09 +0000 (Thu, 03 Sep 2020)");
  script_name("Debian LTS: Security Advisory for uwsgi (DLA-2362-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2362-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'uwsgi'
  package(s) announced via the DLA-2362-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Apache HTTP Server versions before 2.4.32 uses src:uwsgi where a flaw
was discovered. The uwsgi protocol does not let us serialize more
than 16K of HTTP header leading to resource exhaustion and denial of
service.");

  script_tag(name:"affected", value:"'uwsgi' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, this problem has been fixed in version
2.0.14+20161117-3+deb9u3.

We recommend that you upgrade your uwsgi packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-core", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-emperor", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-extra", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-mongodb-plugins", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-curl", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-xmpp", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python3", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-curl-cron", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-emperor-pg", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-gccgo", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-geoip", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-gevent-python", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-glusterfs", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-8", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-8", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ldap", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.2", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-luajit", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-mono", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-php", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby2.3", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rados", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-rbthreads", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-ring-openjdk-8", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-router-access", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-servlet-openjdk-8", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-sqlite3", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-tornado-python", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-v8", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugin-xslt", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"uwsgi-src", ver:"2.0.14+20161117-3+deb9u3", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
