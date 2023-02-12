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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5845.2");
  script_cve_id("CVE-2023-0215", "CVE-2023-0286");
  script_tag(name:"creation_date", value:"2023-02-08 04:10:53 +0000 (Wed, 08 Feb 2023)");
  script_version("2023-02-08T10:09:54+0000");
  script_tag(name:"last_modification", value:"2023-02-08 10:09:54 +0000 (Wed, 08 Feb 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5845-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5845-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5845-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-5845-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5845-1 fixed several vulnerabilities in OpenSSL. This update provides
the corresponding update for Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.

Original advisory details:

 David Benjamin discovered that OpenSSL incorrectly handled X.400 address
 processing. A remote attacker could possibly use this issue to read
 arbitrary memory contents or cause OpenSSL to crash, resulting in a denial
 of service. (CVE-2023-0286)

 Octavio Galland and Marcel Bohme discovered that OpenSSL incorrectly
 handled streaming ASN.1 data. A remote attacker could use this issue to
 cause OpenSSL to crash, resulting in a denial of service, or possibly
 execute arbitrary code. (CVE-2023-0215)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.1f-1ubuntu2.27+esm6", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.0.0", ver:"1.0.2g-1ubuntu4.20+esm6", rls:"UBUNTU16.04 LTS"))) {
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
