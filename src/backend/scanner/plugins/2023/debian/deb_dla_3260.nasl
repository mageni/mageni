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
  script_oid("1.3.6.1.4.1.25623.1.0.893260");
  script_version("2023-01-10T10:12:01+0000");
  script_cve_id("CVE-2021-21366", "CVE-2022-39299", "CVE-2022-39353");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-22 12:09:00 +0000 (Mon, 22 Mar 2021)");
  script_tag(name:"creation_date", value:"2023-01-02 02:00:10 +0000 (Mon, 02 Jan 2023)");
  script_name("Debian LTS: Security Advisory for node-xmldom (DLA-3260-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3260-1");
  script_xref(name:"Advisory-ID", value:"DLA-3260-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1024736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-xmldom'
  package(s) announced via the DLA-3260-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that node-xmldom, a standard XML DOM (Level2 CORE)
implementation in pure javascript, processed ill-formed XML, which may result in
bugs and security holes in downstream applications.

CVE-2021-21366

xmldom versions 0.4.0 and older do not correctly preserve system
identifiers, FPIs or namespaces when repeatedly parsing and serializing
maliciously crafted documents. This may lead to unexpected syntactic
changes during XML processing in some downstream applications.

CVE-2022-39353

Mark Gollnick discovered that xmldom parses XML that is not well-formed
because it contains multiple top level elements, and adds all root nodes to
the `childNodes` collection of the `Document`, without reporting or throwing
any error. This breaks the assumption that there is only a single root node
in the tree, and may open security holes such as CVE-2022-39299 in
downstream applications.");

  script_tag(name:"affected", value:"'node-xmldom' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
0.1.27+ds-1+deb10u2.

We recommend that you upgrade your node-xmldom packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"node-xmldom", ver:"0.1.27+ds-1+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
