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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4934.2");
  script_cve_id("CVE-2020-28007", "CVE-2020-28008", "CVE-2020-28009", "CVE-2020-28011", "CVE-2020-28012", "CVE-2020-28013", "CVE-2020-28014", "CVE-2020-28015", "CVE-2020-28016", "CVE-2020-28017", "CVE-2020-28020", "CVE-2020-28022", "CVE-2020-28024", "CVE-2020-28025", "CVE-2020-28026", "CVE-2021-27216");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-10 16:13:00 +0000 (Mon, 10 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-4934-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4934-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4934-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim4' package(s) announced via the USN-4934-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4934-1 fixed several vulnerabilities in Exim. This update provides
the corresponding update for Ubuntu 14.04 ESM and Ubuntu 16.04 ESM.
CVE-2020-28026 only affected Ubuntu 16.04 ESM.

Original advisory details:

 It was discovered that Exim contained multiple security issues. An attacker
 could use these issues to cause a denial of service, execute arbitrary
 code remotely, obtain sensitive information, or escalate local privileges.");

  script_tag(name:"affected", value:"'exim4' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"exim4-base", ver:"4.82-3ubuntu2.4+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.82-3ubuntu2.4+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.82-3ubuntu2.4+esm3", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"exim4-base", ver:"4.86.2-2ubuntu2.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-heavy", ver:"4.86.2-2ubuntu2.6+esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"exim4-daemon-light", ver:"4.86.2-2ubuntu2.6+esm1", rls:"UBUNTU16.04 LTS"))) {
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
