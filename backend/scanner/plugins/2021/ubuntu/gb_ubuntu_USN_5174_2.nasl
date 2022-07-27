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
  script_oid("1.3.6.1.4.1.25623.1.0.845163");
  script_version("2021-12-24T05:24:58+0000");
  script_cve_id("CVE-2016-2124", "CVE-2020-25717", "CVE-2020-25722", "CVE-2021-3671");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-12-24 11:10:42 +0000 (Fri, 24 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-14 02:00:38 +0000 (Tue, 14 Dec 2021)");
  script_name("Ubuntu: Security Advisory for samba (USN-5174-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04 LTS");

  script_xref(name:"Advisory-ID", value:"USN-5174-2");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-December/006313.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the USN-5174-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5174-1 fixed vulnerabilities in Samba. Some of the changes introduced a
regression in Kerberos authentication in certain environments.

This update fixes the problem.

Original advisory details:

Stefan Metzmacher discovered that Samba incorrectly handled SMB1 client
connections. A remote attacker could possibly use this issue to downgrade
connections to plaintext authentication. (CVE-2016-2124)
Andrew Bartlett discovered that Samba incorrectly mapping domain users to
local users. An authenticated attacker could possibly use this issue to
become root on domain members. (CVE-2020-25717)
Andrew Bartlett discovered that Samba did not properly check sensitive
attributes. An authenticated attacker could possibly use this issue to
escalate privileges. (CVE-2020-25722)
Joseph Sutton discovered that Samba incorrectly handled certain TGS
requests. An authenticated attacker could possibly use this issue to cause
Samba to crash, resulting in a denial of service. (CVE-2021-3671)
The fix for CVE-2020-25717 results in possible behaviour changes that could
affect certain environments.");

  script_tag(name:"affected", value:"'samba' package(s) on Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"samba", ver:"2:4.7.6+dfsg~ubuntu-0ubuntu2.27", rls:"UBUNTU18.04 LTS"))) {
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
