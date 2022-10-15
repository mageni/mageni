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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5675.1");
  script_cve_id("CVE-2018-16860", "CVE-2019-12098", "CVE-2021-3671", "CVE-2022-3116");
  script_tag(name:"creation_date", value:"2022-10-14 04:45:12 +0000 (Fri, 14 Oct 2022)");
  script_version("2022-10-14T04:45:12+0000");
  script_tag(name:"last_modification", value:"2022-10-14 04:45:12 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-14 12:15:00 +0000 (Wed, 14 Aug 2019)");

  script_name("Ubuntu: Security Advisory (USN-5675-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5675-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5675-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'heimdal' package(s) announced via the USN-5675-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Isaac Boukris and Andrew Bartlett discovered that Heimdal's KDC was
not properly performing checksum algorithm verifications in the
S4U2Self extension module. An attacker could possibly use this issue
to perform a machine-in-the-middle attack and request S4U2Self
tickets for any user known by the application. This issue only
affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and Ubuntu 18.04 LTS.
(CVE-2018-16860)

It was discovered that Heimdal was not properly handling the
verification of key exchanges when an anonymous PKINIT was being
used. An attacker could possibly use this issue to perform a
machine-in-the-middle attack and expose sensitive information.
This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 ESM and
Ubuntu 18.04 LTS. (CVE-2019-12098)

Joseph Sutton discovered that Heimdal was not properly handling
memory management operations when dealing with TGS-REQ tickets that
were missing information. An attacker could possibly use this issue
to cause a denial of service. (CVE-2021-3671)

Michal Kepien discovered that Heimdal was not properly handling
logical conditions that related to memory management operations. An
attacker could possibly use this issue to cause a denial of service.
(CVE-2022-3116)");

  script_tag(name:"affected", value:"'heimdal' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients-x", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers-x", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.6~git20131207+dfsg-1ubuntu1.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"1.7~git20150920+dfsg-4ubuntu1.16.04.1+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.5.0+dfsg-1ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-clients", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kcm", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-kdc", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"heimdal-servers", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgssapi3-heimdal", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkdc2-heimdal", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkrb5-26-heimdal", ver:"7.7.0+dfsg-1ubuntu1.1", rls:"UBUNTU20.04 LTS"))) {
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
