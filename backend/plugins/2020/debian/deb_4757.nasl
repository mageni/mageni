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
  script_oid("1.3.6.1.4.1.25623.1.0.704757");
  script_version("2020-09-01T03:00:12+0000");
  script_cve_id("CVE-2020-11984", "CVE-2020-11993", "CVE-2020-1927", "CVE-2020-1934", "CVE-2020-9490");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-01 03:00:12 +0000 (Tue, 01 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-01 03:00:12 +0000 (Tue, 01 Sep 2020)");
  script_name("Debian: Security Advisory for apache2 (DSA-4757-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4757.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4757-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the DSA-4757-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been found in the Apache HTTPD server.

CVE-2020-1927
Fabrice Perez reported that certain mod_rewrite configurations are
prone to an open redirect.

CVE-2020-1934
Chamal De Silva discovered that the mod_proxy_ftp module uses
uninitialized memory when proxying to a malicious FTP backend.

CVE-2020-9490
Felix Wilhelm discovered that a specially crafted value for the
'Cache-Digest' header in a HTTP/2 request could cause a crash when
the server actually tries to HTTP/2 PUSH a resource afterwards.

CVE-2020-11984
Felix Wilhelm reported a buffer overflow flaw in the mod_proxy_uwsgi
module which could result in information disclosure or potentially
remote code execution.

CVE-2020-11993
Felix Wilhelm reported that when trace/debug was enabled for the
HTTP/2 module certain traffic edge patterns can cause logging
statements on the wrong connection, causing concurrent use of
memory pools.");

  script_tag(name:"affected", value:"'apache2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2.4.38-3+deb10u4.

We recommend that you upgrade your apache2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"apache2", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-bin", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-data", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-dev", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-doc", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-ssl-dev", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-custom", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-suexec-pristine", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"apache2-utils", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-md", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-proxy-uwsgi", ver:"2.4.38-3+deb10u4", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
