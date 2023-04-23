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
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5384");
  script_cve_id("CVE-2022-36354", "CVE-2022-41639", "CVE-2022-41649", "CVE-2022-41684", "CVE-2022-41794", "CVE-2022-41837", "CVE-2022-41838", "CVE-2022-41977", "CVE-2022-41981", "CVE-2022-41988", "CVE-2022-41999", "CVE-2022-43592", "CVE-2022-43593", "CVE-2022-43594", "CVE-2022-43595", "CVE-2022-43596", "CVE-2022-43597", "CVE-2022-43598", "CVE-2022-43599", "CVE-2022-43600", "CVE-2022-43601", "CVE-2022-43602", "CVE-2022-43603");
  script_tag(name:"creation_date", value:"2023-04-11 04:27:48 +0000 (Tue, 11 Apr 2023)");
  script_version("2023-04-11T10:10:11+0000");
  script_tag(name:"last_modification", value:"2023-04-11 10:10:11 +0000 (Tue, 11 Apr 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-30 01:37:00 +0000 (Fri, 30 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-5384)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5384");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5384");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5384");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openimageio");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openimageio' package(s) announced via the DSA-5384 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in OpenImageIO, a library for reading and writing images. Buffer overflows and out-of-bounds read and write programming errors may lead to a denial of service (application crash) or the execution of arbitrary code if a malformed image file is processed.

For the stable distribution (bullseye), these problems have been fixed in version 2.2.10.1+dfsg-1+deb11u1.

We recommend that you upgrade your openimageio packages.

For the detailed security status of openimageio please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openimageio' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libopenimageio-dev", ver:"2.2.10.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenimageio-doc", ver:"2.2.10.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libopenimageio2.2", ver:"2.2.10.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openimageio-tools", ver:"2.2.10.1+dfsg-1+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-openimageio", ver:"2.2.10.1+dfsg-1+deb11u1", rls:"DEB11"))) {
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
