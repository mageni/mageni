# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893236");
  script_version("2022-12-13T10:10:56+0000");
  script_cve_id("CVE-2020-16587", "CVE-2020-16588", "CVE-2020-16589", "CVE-2021-20296", "CVE-2021-20298", "CVE-2021-20299", "CVE-2021-20300", "CVE-2021-20302", "CVE-2021-20303", "CVE-2021-23215", "CVE-2021-26260", "CVE-2021-3474", "CVE-2021-3475", "CVE-2021-3476", "CVE-2021-3477", "CVE-2021-3478", "CVE-2021-3479", "CVE-2021-3598", "CVE-2021-3605", "CVE-2021-3933", "CVE-2021-3941", "CVE-2021-45942");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-17 01:05:00 +0000 (Thu, 17 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-12-12 02:00:25 +0000 (Mon, 12 Dec 2022)");
  script_name("Debian LTS: Security Advisory for openexr (DLA-3236-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00022.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3236-1");
  script_xref(name:"Advisory-ID", value:"DLA-3236-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/986796");
  script_xref(name:"URL", value:"https://bugs.debian.org/992703");
  script_xref(name:"URL", value:"https://bugs.debian.org/990450");
  script_xref(name:"URL", value:"https://bugs.debian.org/990899");
  script_xref(name:"URL", value:"https://bugs.debian.org/1014828");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openexr'
  package(s) announced via the DLA-3236-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been found in OpenEXR, command-line
tools and a library for the OpenEXR image format. Buffer overflows or
out-of-bound reads could lead to a denial of service (application crash) if
a malformed image file is processed.");

  script_tag(name:"affected", value:"'openexr' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
2.2.1-4.1+deb10u2.

We recommend that you upgrade your openexr packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libopenexr-dev", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libopenexr23", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openexr", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"openexr-doc", ver:"2.2.1-4.1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
