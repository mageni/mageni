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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5477.1");
  script_cve_id("CVE-2017-16879", "CVE-2018-19211", "CVE-2019-17594", "CVE-2019-17595", "CVE-2021-39537", "CVE-2022-29458");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-02 02:14:00 +0000 (Sat, 02 Oct 2021)");

  script_name("Ubuntu: Security Advisory (USN-5477-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5477-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5477-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses' package(s) announced via the USN-5477-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hosein Askari discovered that ncurses was incorrectly performing
memory management operations when dealing with long filenames while
writing structures into the file system. An attacker could possibly
use this issue to cause a denial of service or execute arbitrary
code. (CVE-2017-16879)

Chung-Yi Lin discovered that ncurses was incorrectly handling access
to invalid memory areas when parsing terminfo or termcap entries where
the use-name had invalid syntax. An attacker could possibly use this
issue to cause a denial of service. (CVE-2018-19211)

It was discovered that ncurses was incorrectly performing bounds
checks when processing invalid hashcodes. An attacker could possibly
use this issue to cause a denial of service or to expose sensitive
information. (CVE-2019-17594)

It was discovered that ncurses was incorrectly handling
end-of-string characters when processing terminfo and termcap files.
An attacker could possibly use this issue to cause a denial of
service or to expose sensitive information. (CVE-2019-17595)

It was discovered that ncurses was incorrectly handling
end-of-string characters when converting between termcap and
terminfo formats. An attacker could possibly use this issue to cause
a denial of service or execute arbitrary code. (CVE-2021-39537)

It was discovered that ncurses was incorrectly performing bounds
checks when dealing with corrupt terminfo data while reading a
terminfo file. An attacker could possibly use this issue to cause a
denial of service or to expose sensitive information.
(CVE-2022-29458)");

  script_tag(name:"affected", value:"'ncurses' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libncurses5", ver:"5.9+20140118-1ubuntu1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo5", ver:"5.9+20140118-1ubuntu1+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-bin", ver:"5.9+20140118-1ubuntu1+esm2", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libncurses5", ver:"6.0+20160213-1ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo5", ver:"6.0+20160213-1ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-bin", ver:"6.0+20160213-1ubuntu1+esm2", rls:"UBUNTU16.04 LTS"))) {
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
