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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6146.1");
  script_cve_id("CVE-2021-31439", "CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122", "CVE-2022-23123", "CVE-2022-23124", "CVE-2022-23125", "CVE-2022-43634", "CVE-2022-45188");
  script_tag(name:"creation_date", value:"2023-06-09 04:09:38 +0000 (Fri, 09 Jun 2023)");
  script_version("2023-06-09T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-06-09 05:05:15 +0000 (Fri, 09 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 14:00:00 +0000 (Fri, 07 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-6146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6146-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6146-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netatalk' package(s) announced via the USN-6146-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Netatalk did not properly validate the length of
user-supplied data in the DSI structures. A remote attacker could possibly
use this issue to execute arbitrary code with the privileges of the user
invoking the programs. This issue only affected Ubuntu 20.04 LTS and Ubuntu
22.04 LTS. (CVE-2021-31439)

It was discovered that Netatalk did not properly validate the length of
user-supplied data in the ad_addcomment function. A remote attacker could
possibly use this issue to execute arbitrary code with root privileges.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-0194)

It was discovered that Netatalk did not properly handle errors when parsing
AppleDouble entries. A remote attacker could possibly use this issue to
execute arbitrary code with root privileges. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, Ubuntu 20.04 LTS and
Ubuntu 22.04 LTS. (CVE-2022-23121)

It was discovered that Netatalk did not properly validate the length of
user-supplied data in the setfilparams function. A remote attacker could
possibly use this issue to execute arbitrary code with root privileges.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-23122)

It was discovered that Netatalk did not properly validate the length of
user-supplied data in the getdirparams function. A remote attacker could
possibly use this issue to execute arbitrary code with root privileges.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04
LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2022-23123)

It was discovered that Netatalk did not properly validate the length of
user-supplied data in the get_finderinfo function. A remote attacker could
possibly use this issue to execute arbitrary code with root privileges.
This issue only affected Ubuntu 20.04 LTS and Ubuntu 22.04 LTS.
(CVE-2022-23124)

It was discovered that Netatalk did not properly validate the length of
user-supplied data in the copyapplfile function. A remote attacker could
possibly use this issue to execute arbitrary code with root privileges.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04
LTS, Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2022-23125)

It was discovered that Netatalk did not properly validate the length of
user-supplied data in the dsi_writeinit function. A remote attacker could
possibly use this issue to execute arbitrary code with root privileges.
This issue only affected Ubuntu 20.04 LTS, Ubuntu 22.04 LTS and Ubuntu
22.10. (CVE-2022-43634)

It was discovered that Netatalk did not properly manage memory under
certain circumstances. If a user were tricked into opening a specially
crafted .appl file, a remote attacker could possibly use this issue to
execute arbitrary code. (CVE-2022-45188)");

  script_tag(name:"affected", value:"'netatalk' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"2.2.2-1ubuntu2.2+esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"2.2.5-1ubuntu0.2+esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"2.2.6-1ubuntu0.18.04.2+esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"3.1.12~ds-4ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"3.1.12~ds-9ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"3.1.13~ds-2ubuntu0.22.10.1", rls:"UBUNTU22.10"))) {
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
