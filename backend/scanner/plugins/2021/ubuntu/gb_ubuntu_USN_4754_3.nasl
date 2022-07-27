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
  script_oid("1.3.6.1.4.1.25623.1.0.844864");
  script_version("2021-03-17T09:33:35+0000");
  script_cve_id("CVE-2019-9674", "CVE-2019-17514", "CVE-2019-20907", "CVE-2020-8492", "CVE-2020-26116", "CVE-2020-27619", "CVE-2021-3177");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-03-17 11:26:15 +0000 (Wed, 17 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-13 04:00:18 +0000 (Sat, 13 Mar 2021)");
  script_name("Ubuntu: Security Advisory for python2.7 (USN-4754-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4754-3");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-March/005929.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7'
  package(s) announced via the USN-4754-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4754-1 fixed vulnerabilities in Python. This update provides
the corresponding updates for Ubuntu 18.04 ESM and Ubuntu 20.04 ESM.

In the case of Python 2.7 for 20.04 ESM, these additional fixes are included:

It was discovered that Python allowed remote attackers to cause a denial of
service (resource consumption) via a ZIP bomb. (CVE-2019-9674)

It was discovered that Python had potentially misleading information about
whether sorting occurs. This fix updates the documentation about it.
(CVE-2019-17514)

It was discovered that Python incorrectly handled certain TAR archives.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2019-20907)

It was discovered that Python allowed an HTTP server to conduct Regular
Expression Denial of Service (ReDoS) attacks against a client because of
urllib.request.AbstractBasicAuthHandler catastrophic backtracking.
(CVE-2020-8492)

It was discovered that Python allowed CRLF injection if the attacker controls
the HTTP request method, as demonstrated by inserting CR and LF control
characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

Original advisory details:

It was discovered that Python incorrectly handled certain inputs.
An attacker could possibly use this issue to execute arbitrary code
or cause a denial of service. (CVE-2020-27619, CVE-2021-3177)");

  script_tag(name:"affected", value:"'python2.7' package(s) on Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3.7", ver:"3.7.5-2~18.04.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.7-minimal", ver:"3.7.5-2~18.04.4", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8", ver:"3.8.0-3~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.8-minimal", ver:"3.8.0-3~18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.18-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.18-1~20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
