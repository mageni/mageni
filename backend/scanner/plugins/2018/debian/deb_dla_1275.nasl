###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1275.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1275-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.891275");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-6758");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1275-1] uwsgi security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-02-21 00:00:00 +0100 (Wed, 21 Feb 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/02/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"uwsgi on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.2.3+dfsg-5+deb7u2.

We recommend that you upgrade your uwsgi packages.");
  script_tag(name:"summary", value:"It was discovered that the uwsgi_expand_path function in utils.c in
Unbit uWSGI, an application container server, has a stack-based buffer
overflow via a large directory length that can cause a
denial-of-service (application crash) or stack corruption.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-ruwsgi-dbg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-uwsgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"libapache2-mod-uwsgi-dbg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-django-uwsgi-admin", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-uwsgicc", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python-uwsgidecorators", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"python3-uwsgidecorators", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-app-integration-plugins", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-core", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-dbg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-extra", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-infrastructure-plugins", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-admin", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-cache", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-carbon", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-cgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-echo", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-erlang", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-fastrouter", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-fiber", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-graylog2", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-greenlet-python", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-http", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-jvm-openjdk-6", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-jwsgi-openjdk-6", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-logsocket", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-lua5.1", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-nagios", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-ping", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-probeconnect", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-probepg", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-psgi", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-pyerl-python", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-pyerl-python3", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-python", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-python3", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby1.8", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rack-ruby1.9.1", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rpc", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rrdtool", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-rsyslog", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-signal", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-symcall", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-syslog", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugin-ugreen", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"uwsgi-plugins-all", ver:"1.2.3+dfsg-5+deb7u2", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}