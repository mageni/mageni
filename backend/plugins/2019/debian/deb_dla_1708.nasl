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
  script_oid("1.3.6.1.4.1.25623.1.0.891708");
  script_version("$Revision: 14282 $");
  script_cve_id("CVE-2016-10742", "CVE-2017-2826");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1708-1] zabbix security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:55:18 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-12 00:00:00 +0100 (Tue, 12 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00010.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"zabbix on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:2.2.23+dfsg-0+deb8u1.

We recommend that you upgrade your zabbix packages.");
  script_tag(name:"summary", value:"Several security vulnerabilities were discovered in Zabbix, a
server/client network monitoring solution.

CVE-2016-10742

Zabbix allowed remote attackers to redirect to external links by
misusing the request parameter.

CVE-2017-2826

An information disclosure vulnerability exists in the iConfig proxy
request of Zabbix server. A specially crafted iConfig proxy request
can cause the Zabbix server to send the configuration information of
any Zabbix proxy, resulting in information disclosure. An attacker
can make requests from an active Zabbix proxy to trigger this
vulnerability.

This update also includes several other bug fixes and improvements. For
more information please refer to the upstream changelog file.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"zabbix-agent", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-frontend-php", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-java-gateway", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-proxy-mysql", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-proxy-pgsql", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-proxy-sqlite3", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-server-mysql", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"zabbix-server-pgsql", ver:"1:2.2.23+dfsg-0+deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}