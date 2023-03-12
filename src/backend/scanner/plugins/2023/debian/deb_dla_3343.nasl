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
  script_oid("1.3.6.1.4.1.25623.1.0.893343");
  script_cve_id("CVE-2023-26314");
  script_tag(name:"creation_date", value:"2023-02-26 02:00:04 +0000 (Sun, 26 Feb 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-02 20:03:00 +0000 (Thu, 02 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3343)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3343");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3343");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mono");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mono' package(s) announced via the DLA-3343 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Triggering arbitrary code execution was possible due to .desktop files registered as application/x-ms-dos-executable MIME handlers in the open source .NET framework Mono.

For Debian 10 buster, this problem has been fixed in version 5.18.0.240+dfsg-3+deb10u1.

We recommend that you upgrade your mono packages.

For the detailed security status of mono please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mono' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"ca-certificates-mono", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-2.0-1", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-2.0-dev", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-accessibility4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-btls-interface4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cairo4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cecil-private-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cil-dev", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-codecontracts4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-compilerservices-symbolwriter4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-corlib4.5-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-cscompmgd0.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-csharp4.0c-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-custommarshalers4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-data-tds4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-db2-1.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-debugger-soft4.0a-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-http4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-cjk4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-mideast4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-other4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-rare4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n-west4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n4.0-all", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-i18n4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-ldap4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-management4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging-rabbitmq4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-messaging4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-engine4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-framework4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-tasks-v4.0-4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build-utilities-v4.0-4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-build4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-csharp4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-visualc10.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-microsoft-web-infrastructure1.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-oracle4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-parallel4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-peapi4.0a-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-posix4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-profiler", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-rabbitmq4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-relaxng4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-security4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sharpzip4.84-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-simd4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-smdiagnostics0.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-sqlite4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-componentmodel-composition4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-componentmodel-dataannotations4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-configuration-install4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-configuration4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-core4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-datasetextensions4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-entity4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-linq4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-services-client4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data-services4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-data4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-deployment4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-design4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-drawing-design4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-drawing4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-dynamic4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-enterpriseservices4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-identitymodel-selectors4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-identitymodel4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-io-compression-filesystem4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-io-compression4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-json-microsoft4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-json4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap-protocols4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-ldap4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-management4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-messaging4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-net-http-formatting4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-net-http-webrequest4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-net-http4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-net4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-numerics-vectors4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-numerics4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-core2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-debugger2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-experimental2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-interfaces2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-linq2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-observable-aliases0.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-platformservices2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-providers2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-runtime-remoting2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-windows-forms2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reactive-windows-threading2.2-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-reflection-context4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-caching4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-durableinstancing4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-serialization-formatters-soap4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime-serialization4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-runtime4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-security4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-activation4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-discovery4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-internals0.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-routing4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel-web4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-servicemodel4.0a-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-serviceprocess4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-threading-tasks-dataflow4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-transactions4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-abstractions4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-applicationservices4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-dynamicdata4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-extensions-design4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-extensions4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-http-selfhost4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-http-webhost4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-http4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mobile4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-mvc3.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-razor2.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-regularexpressions4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-routing4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-services4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-webpages-deployment2.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-webpages-razor2.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web-webpages2.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-web4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-windows-forms-datavisualization4.0a-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-windows-forms4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-windows4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-workflow-activities4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-workflow-componentmodel4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-workflow-runtime4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xaml4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xml-linq4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xml-serialization4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system-xml4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-system4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-tasklets4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webbrowser4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-webmatrix-data4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-windowsbase4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmono-xbuild-tasks4.0-cil", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmonoboehm-2.0-1-dbg", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmonoboehm-2.0-1", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmonoboehm-2.0-dev", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmonosgen-2.0-1-dbg", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmonosgen-2.0-1", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmonosgen-2.0-dev", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-4.0-gac", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-4.0-service", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-complete", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-csharp-shell", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-dbg", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-devel", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-gac", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-jay", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-mcs", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-boehm", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-common", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-dbg", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime-sgen", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-runtime", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-source", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-utils", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mono-xbuild", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-base", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"monodoc-manual", ver:"5.18.0.240+dfsg-3+deb10u1", rls:"DEB10"))) {
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
