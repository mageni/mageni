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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5391");
  script_cve_id("CVE-2023-28484", "CVE-2023-29469");
  script_tag(name:"creation_date", value:"2023-04-21 04:24:27 +0000 (Fri, 21 Apr 2023)");
  script_version("2023-04-21T04:24:27+0000");
  script_tag(name:"last_modification", value:"2023-04-21 04:24:27 +0000 (Fri, 21 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5391)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5391");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5391");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5391");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxml2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-5391 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libxml2, a library providing support to read, modify and write XML and HTML files.

CVE-2023-28484

A NULL pointer dereference flaw when parsing invalid XML schemas may result in denial of service.

CVE-2023-29469

It was reported that when hashing empty strings which aren't null-terminated, xmlDictComputeFastKey could produce inconsistent results, which may lead to various logic or memory errors.

For the stable distribution (bullseye), these problems have been fixed in version 2.9.10+dfsg-6.7+deb11u4.

We recommend that you upgrade your libxml2 packages.

For the detailed security status of libxml2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-dev", ver:"2.9.10+dfsg-6.7+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-doc", ver:"2.9.10+dfsg-6.7+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2-utils", ver:"2.9.10+dfsg-6.7+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.10+dfsg-6.7+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2-dbg", ver:"2.9.10+dfsg-6.7+deb11u4", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2", ver:"2.9.10+dfsg-6.7+deb11u4", rls:"DEB11"))) {
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
