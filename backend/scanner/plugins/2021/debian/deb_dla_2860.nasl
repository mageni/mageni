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
  script_oid("1.3.6.1.4.1.25623.1.0.892860");
  script_version("2021-12-31T03:03:17+0000");
  script_cve_id("CVE-2018-1000805", "CVE-2018-7750");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-31 11:42:39 +0000 (Fri, 31 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:31:00 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2021-12-29 02:00:17 +0000 (Wed, 29 Dec 2021)");
  script_name("Debian LTS: Security Advisory for paramiko (DLA-2860-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/12/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2860-1");
  script_xref(name:"Advisory-ID", value:"DLA-2860-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/892859");
  script_xref(name:"URL", value:"https://bugs.debian.org/910760");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'paramiko'
  package(s) announced via the DLA-2860-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A couple of vulnerabilities were found in paramiko, an implementation
of SSHv2 protocol in Python.

CVE-2018-1000805

Fix to prevent malicious clients to trick the Paramiko server
into thinking an unauthenticated client is authenticated.

CVE-2018-7750

Fix check whether authentication is completed before processing
other requests. A customized SSH client can simply skip the
authentication step.");

  script_tag(name:"affected", value:"'paramiko' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.0.0-1+deb9u1.

We recommend that you upgrade your paramiko packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"paramiko-doc", ver:"2.0.0-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python-paramiko", ver:"2.0.0-1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3-paramiko", ver:"2.0.0-1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
