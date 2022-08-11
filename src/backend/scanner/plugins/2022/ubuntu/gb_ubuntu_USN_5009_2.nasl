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
  script_oid("1.3.6.1.4.1.25623.1.0.845223");
  script_version("2022-02-01T06:17:45+0000");
  script_cve_id("CVE-2020-29129", "CVE-2020-29130", "CVE-2021-3592", "CVE-2021-3593", "CVE-2021-3594", "CVE-2021-3595");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-01 11:05:08 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-01-28 08:01:51 +0000 (Fri, 28 Jan 2022)");
  script_name("Ubuntu: Security Advisory for libslirp (USN-5009-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU21\.10");

  script_xref(name:"Advisory-ID", value:"USN-5009-2");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-October/006256.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libslirp'
  package(s) announced via the USN-5009-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5009-1 fixed vulnerabilities in libslirp. This update provides the
corresponding updates for Ubuntu 21.10.

Original advisory details:

Qiuhao Li discovered that libslirp incorrectly handled certain header data
lengths. An attacker inside a guest could possibly use this issue to leak
sensitive information from the host. This issue only affected Ubuntu 20.04
LTS and Ubuntu 20.10. (CVE-2020-29129, CVE-2020-29130)
It was discovered that libslirp incorrectly handled certain udp packets. An
attacker inside a guest could possibly use this issue to leak sensitive
information from the host. (CVE-2021-3592, CVE-2021-3593, CVE-2021-3594,
CVE-2021-3595)");

  script_tag(name:"affected", value:"'libslirp' package(s) on Ubuntu 21.10.");

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

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libslirp0", ver:"4.4.0-1ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
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