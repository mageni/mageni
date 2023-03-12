# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.176");
  script_cve_id("CVE-2015-2318", "CVE-2015-2319", "CVE-2015-2320");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-30 19:21:00 +0000 (Tue, 30 Jan 2018)");

  script_name("Debian: Security Advisory (DLA-176)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-176");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-176");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mono' package(s) announced via the DLA-176 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three issues with Mono's TLS stack are addressed.

CVE-2015-2318

Mono's implementation of the SSL/TLS stack failed to check the order of the handshake messages. Which would allow various attacks on the protocol to succeed. ('SKIP-TLS')

CVE-2015-2319

Mono's implementation of SSL/TLS also contained support for the weak EXPORT cyphers and was susceptible to the FREAK attack.

CVE-2015-2320

Mono contained SSLv2 fallback code, which is no longer needed and can be considered insecure.

For Debian 6 Squeeze, these issues have been fixed in mono version 2.6.7-5.1+deb6u1");

  script_tag(name:"affected", value:"'mono' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.1-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-bytefx0.7.6.2-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-c5-1.1-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cecil-private-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cil-dev", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cscompmgd7.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cscompmgd8.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-debugger-soft0.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-dev", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-firebirdsql1.7-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-getoptions1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-getoptions2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-management2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft7.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft8.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-npgsql1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-npgsql2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-profiler", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-rabbitmq2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip0.6-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip0.84-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip2.6-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip2.84-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-simd2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-linq2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-tasklets2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-wcf3.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webbrowser0.5-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-windowsbase3.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-winforms1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-winforms2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono0-dbg", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono0", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono1.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono2.0-cil", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-1.0-devel", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-1.0-gac", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-1.0-service", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-devel", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-gac", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-2.0-service", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-complete", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-csharp-shell", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-dbg", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-devel", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gac", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gmcs", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-jay", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-mcs", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-mjs", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-dbg", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-utils", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-xbuild", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-base", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-manual", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"prj2make-sharp", ver:"2.6.7-5.1+deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
