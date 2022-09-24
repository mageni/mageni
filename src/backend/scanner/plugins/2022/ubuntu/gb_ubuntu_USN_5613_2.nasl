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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5613.2");
  script_cve_id("CVE-2022-0943", "CVE-2022-1154", "CVE-2022-1420", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620", "CVE-2022-1621");
  script_tag(name:"creation_date", value:"2022-09-20 04:41:34 +0000 (Tue, 20 Sep 2022)");
  script_version("2022-09-20T10:11:40+0000");
  script_tag(name:"last_modification", value:"2022-09-20 10:11:40 +0000 (Tue, 20 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-16 22:15:00 +0000 (Mon, 16 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5613-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5613-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5613-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1989973");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-5613-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5613-1 fixed vulnerabilities in Vim. Unfortunately that update failed
to include binary packages for some architectures. This update fixes that
regression.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Vim was not properly performing bounds checks
 when executing spell suggestion commands. An attacker could possibly use
 this issue to cause a denial of service or execute arbitrary code.
 (CVE-2022-0943)

 It was discovered that Vim was using freed memory when dealing with
 regular expressions through its old regular expression engine. If a user
 were tricked into opening a specially crafted file, an attacker could
 crash the application, leading to a denial of service, or possibly achieve
 code execution. (CVE-2022-1154)

 It was discovered that Vim was not properly performing checks on name of
 lambda functions. An attacker could possibly use this issue to cause a
 denial of service. This issue affected only Ubuntu 22.04 LTS.
 (CVE-2022-1420)

 It was discovered that Vim was incorrectly performing bounds checks
 when processing invalid commands with composing characters in Ex
 mode. An attacker could possibly use this issue to cause a denial of
 service or execute arbitrary code. (CVE-2022-1616)

 It was discovered that Vim was not properly processing latin1 data
 when issuing Ex commands. An attacker could possibly use this issue to
 cause a denial of service or execute arbitrary code. (CVE-2022-1619)

 It was discovered that Vim was not properly performing memory
 management when dealing with invalid regular expression patterns in
 buffers. An attacker could possibly use this issue to cause a denial of
 service. (CVE-2022-1620)

 It was discovered that Vim was not properly processing invalid bytes
 when performing spell check operations. An attacker could possibly use
 this issue to cause a denial of service or execute arbitrary code.
 (CVE-2022-1621)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.1.2269-1ubuntu5.9", rls:"UBUNTU20.04 LTS"))) {
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
