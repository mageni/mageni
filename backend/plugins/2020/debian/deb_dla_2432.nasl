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
  script_oid("1.3.6.1.4.1.25623.1.0.892432");
  script_version("2020-11-20T04:00:21+0000");
  script_cve_id("CVE-2018-19351", "CVE-2018-21030", "CVE-2018-8768");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-20 11:31:44 +0000 (Fri, 20 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-20 04:00:21 +0000 (Fri, 20 Nov 2020)");
  script_name("Debian LTS: Security Advisory for jupyter-notebook (DLA-2432-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00033.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2432-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/893436");
  script_xref(name:"URL", value:"https://bugs.debian.org/917409");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jupyter-notebook'
  package(s) announced via the DLA-2432-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in jupyter-notebook.

CVE-2018-8768

A maliciously forged notebook file can bypass sanitization to execute
Javascript in the notebook context. Specifically, invalid HTML is
'fixed' by jQuery after sanitization, making it dangerous.

CVE-2018-19351

allows XSS via an untrusted notebook because nbconvert responses are
considered to have the same origin as the notebook server.

CVE-2018-21030

jupyter-notebook does not use a CSP header to treat served files as
belonging to a separate origin. Thus, for example, an XSS payload can
be placed in an SVG document.");

  script_tag(name:"affected", value:"'jupyter-notebook' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.2.3-4+deb9u1.

We recommend that you upgrade your jupyter-notebook packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"jupyter-notebook", ver:"4.2.3-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-notebook", ver:"4.2.3-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-notebook-doc", ver:"4.2.3-4+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-notebook", ver:"4.2.3-4+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
