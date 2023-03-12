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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.410");
  script_cve_id("CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-410)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-410");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-410");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DLA-410 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Oracle Java platform, resulting in breakouts of the Java sandbox, information disclosure, denial of service and insecure cryptography.

CVE-2015-7575

A flaw was found in the way TLS 1.2 could use the MD5 hash function for signing ServerKeyExchange and Client Authentication packets during a TLS handshake.

CVE-2015-8126

Multiple buffer overflows in the (1) png_set_PLTE and (2) png_get_PLTE functions in libpng before 1.0.64, 1.1.x and 1.2.x before 1.2.54, 1.3.x and 1.4.x before 1.4.17, 1.5.x before 1.5.24, and 1.6.x before 1.6.19 allow remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a small bit-depth value in an IHDR (aka image header) chunk in a PNG image.

CVE-2015-8472

Buffer overflow in the png_set_PLTE function in libpng before 1.0.65, 1.1.x and 1.2.x before 1.2.55, 1.3.x, 1.4.x before 1.4.18, 1.5.x before 1.5.25, and 1.6.x before 1.6.20 allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact via a small bit-depth value in an IHDR (aka image header) chunk in a PNG image. NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-8126.

CVE-2016-0402

Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105, 7u91, and 8u66 and Java SE Embedded 8u65 allows remote attackers to affect integrity via unknown vectors related to Networking.

CVE-2016-0448

Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105, 7u91, and 8u66, and Java SE Embedded 8u65 allows remote authenticated users to affect confidentiality via vectors related to JMX.

CVE-2016-0466

It was discovered that the JAXP component in OpenJDK did not properly enforce the totalEntitySizeLimit limit. An attacker able to make a Java application process a specially crafted XML file could use this flaw to make the application consume an excessive amount of memory.

CVE-2016-0483

Unspecified vulnerability in the Java SE, Java SE Embedded, and JRockit components in Oracle Java SE 6u105, 7u91, and 8u66, Java SE Embedded 8u65, and JRockit R28.3.8 allows remote attackers to affect confidentiality, integrity, and availability via vectors related to AWT.

CVE-2016-0494

Unspecified vulnerability in the Java SE and Java SE Embedded components in Oracle Java SE 6u105, 7u91, and 8u66 and Java SE Embedded 8u65 allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to 2D.

For Debian 6 Squeeze, these problems have been fixed in version 6b38-1.13.10-1~deb6u1.

We recommend that you upgrade your openjdk-6 packages.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 6.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedtea-6-jre-cacao", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-dbg", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-demo", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-doc", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jdk", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-headless", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-lib", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre-zero", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-jre", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-6-source", ver:"6b38-1.13.10-1~deb6u1", rls:"DEB6"))) {
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
