# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892705");
  script_version("2021-07-09T03:00:10+0000");
  script_cve_id("CVE-2021-30485", "CVE-2021-31229", "CVE-2021-31347", "CVE-2021-31348", "CVE-2021-31598");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-07-09 11:26:32 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-09 03:00:10 +0000 (Fri, 09 Jul 2021)");
  script_name("Debian LTS: Security Advisory for scilab (DLA-2705-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/07/msg00005.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2705-1");
  script_xref(name:"Advisory-ID", value:"DLA-2705-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'scilab'
  package(s) announced via the DLA-2705-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in scilab, particularly in ezXML embedded library:

CVE-2021-30485

Descriptionincorrect memory handling, leading to a NULL pointer dereference
in ezxml_internal_dtd()

CVE-2021-31229

Out-of-bounds write in ezxml_internal_dtd() leading to out-of-bounds write
of a one byte constant

CVE-2021-31347, CVE-2021-31348

incorrect memory handling in ezxml_parse_str() leading to out-of-bounds read

CVE-2021-31598

Out-of-bounds write in ezxml_decode() leading to heap corruption");

  script_tag(name:"affected", value:"'scilab' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
5.5.2-4+deb9u1.

We recommend that you upgrade your scilab packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"scilab", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-cli", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-data", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-doc", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-doc-fr", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-doc-ja", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-doc-pt-br", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-full-bin", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-full-bin-dbg", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-include", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-minimal-bin", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-minimal-bin-dbg", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"scilab-test", ver:"5.5.2-4+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
