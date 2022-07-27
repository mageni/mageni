###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_4142.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DSA 4142-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.704142");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-6758", "CVE-2018-7490");
  script_name("Debian Security Advisory DSA 4142-1 (uwsgi - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-03-17 00:00:00 +0100 (Sat, 17 Mar 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4142.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(8|9)");
  script_tag(name:"affected", value:"uwsgi on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (jessie), this problem has been fixed
in version 2.0.7-1+deb8u2. This update additionally includes the fix for
CVE-2018-6758
which was aimed to be addressed in the upcoming jessie
point release.

For the stable distribution (stretch), this problem has been fixed in
version 2.0.14+20161117-3+deb9u2.

We recommend that you upgrade your uwsgi packages.

For the detailed security status of uwsgi please refer to its security
tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/uwsgi");
  script_tag(name:"summary", value:"Marios Nicolaides discovered that the PHP plugin in uWSGI, a fast,
self-healing application container server, does not properly handle a
DOCUMENT_ROOT check during use of the --php-docroot option, allowing a
remote attacker to mount a directory traversal attack and gain
unauthorized read access to sensitive files located outside of the web
root directory.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-core", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-emperor", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-extra", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-curl", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-xmpp", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-curl-cron", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-emperor-pg", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-geoip", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-7", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-7", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-ldap", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.2", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-luajit", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-php", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby2.1", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rados", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rbthreads", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-router-access", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-sqlite3", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-v8", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-xslt", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"2.0.7-1+deb8u2", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-core", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-emperor", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-extra", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-mongodb-plugins", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-curl", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-alarm-xmpp", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-asyncio-python3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-curl-cron", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-emperor-pg", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-gccgo", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-geoip", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-gevent-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-glusterfs", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-ldap", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.2", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-luajit", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-mono", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-php", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby2.3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rados", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rbthreads", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-ring-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-router-access", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-servlet-openjdk-8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-sqlite3", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-tornado-python", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-v8", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-xslt", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-src", ver:"2.0.14+20161117-3+deb9u2", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}