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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5504.1");
  script_cve_id("CVE-2022-2200", "CVE-2022-34468", "CVE-2022-34470", "CVE-2022-34471", "CVE-2022-34472", "CVE-2022-34473", "CVE-2022-34474", "CVE-2022-34475", "CVE-2022-34476", "CVE-2022-34477", "CVE-2022-34479", "CVE-2022-34480", "CVE-2022-34481", "CVE-2022-34482", "CVE-2022-34483", "CVE-2022-34484", "CVE-2022-34485");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-5504-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|21\.10)");

  script_xref(name:"Advisory-ID", value:"USN-5504-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5504-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5504-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, spoof the
browser UI, bypass CSP restrictions, bypass sandboxed iframe restrictions,
obtain sensitive information, bypass the HTML sanitizer, or execute
arbitrary code. (CVE-2022-2200, CVE-2022-34468, CVE-2022-34470,
CVE-2022-34473, CVE-2022-34474, CVE-2022-34475, CVE-2022-34476,
CVE-2022-34477, CVE-2022-34479, CVE-2022-34480, CVE-2022-34481,
CVE-2022-34484, CVE-2022-34485)

It was discovered that Firefox could be made to save an image with an
executable extension in the filename when dragging and dropping an image
in some circumstances. If a user were tricked into dragging and dropping
a specially crafted image, an attacker could potentially exploit this to
trick the user into executing arbitrary code. (CVE-2022-34482,
CVE-2022-34483)

It was discovered that a compromised server could trick Firefox into an
addon downgrade in some circumstances. An attacker could potentially
exploit this to trick the browser into downgrading an addon to a prior
version. (CVE-2022-34471)

It was discovered that an unavailable PAC file caused OCSP requests to
be blocked, resulting in incorrect error pages being displayed.
(CVE-2022-34472)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"102.0+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"102.0+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"102.0+build2-0ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
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
