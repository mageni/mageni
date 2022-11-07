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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5710.1");
  script_cve_id("CVE-2022-3358", "CVE-2022-3602", "CVE-2022-3786");
  script_tag(name:"creation_date", value:"2022-11-02 04:34:55 +0000 (Wed, 02 Nov 2022)");
  script_version("2022-11-04T04:25:59+0000");
  script_tag(name:"last_modification", value:"2022-11-04 04:25:59 +0000 (Fri, 04 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-03 01:15:00 +0000 (Thu, 03 Nov 2022)");

  script_name("Ubuntu: Security Advisory (USN-5710-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5710-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5710-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-5710-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenSSL incorrectly handled certain X.509 Email
Addresses. If a certificate authority were tricked into signing a
specially-crafted certificate, a remote attacker could possibly use this
issue to cause OpenSSL to crash, resulting in a denial of service. The
default compiler options for affected releases reduce the vulnerability to
a denial of service. (CVE-2022-3602, CVE-2022-3786)

It was discovered that OpenSSL incorrectly handled applications creating
custom ciphers via the legacy EVP_CIPHER_meth_new() function. This issue
could cause certain applications that mishandled values to the function to
possibly end up with a NULL cipher and messages in plaintext.
(CVE-2022-3358)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 22.04, Ubuntu 22.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.5-2ubuntu2", rls:"UBUNTU22.10"))) {
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
