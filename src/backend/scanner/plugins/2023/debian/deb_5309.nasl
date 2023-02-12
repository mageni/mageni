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
  script_oid("1.3.6.1.4.1.25623.1.0.705309");
  script_version("2023-01-10T10:12:01+0000");
  script_cve_id("CVE-2022-42852", "CVE-2022-42856", "CVE-2022-42867", "CVE-2022-46692", "CVE-2022-46698", "CVE-2022-46699", "CVE-2022-46700");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-01 02:00:10 +0000 (Sun, 01 Jan 2023)");
  script_name("Debian: Security Advisory for wpewebkit (DSA-5309-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5309.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5309-1");
  script_xref(name:"Advisory-ID", value:"DSA-5309-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpewebkit'
  package(s) announced via the DSA-5309-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities have been discovered in the WPE WebKit
web engine:

CVE-2022-42852
hazbinhotel discovered that processing maliciously crafted web
content may result in the disclosure of process memory.

CVE-2022-42856
Clement Lecigne discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2022-42867
Maddie Stone discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2022-46692
KirtiKumar Anandrao Ramchandani discovered that processing
maliciously crafted web content may bypass Same Origin Policy.

CVE-2022-46698
Dohyun Lee and Ryan Shin discovered that processing maliciously
crafted web content may disclose sensitive user information.

CVE-2022-46699
Samuel Gross discovered that processing maliciously crafted web
content may lead to arbitrary code execution.

CVE-2022-46700
Samuel Gross discovered that processing maliciously crafted web
content may lead to arbitrary code execution.");

  script_tag(name:"affected", value:"'wpewebkit' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 2.38.3-1~deb11u1.

We recommend that you upgrade your wpewebkit packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-3", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-dev", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwpewebkit-1.0-doc", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"wpewebkit-driver", ver:"2.38.3-1~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
