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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2020.4252.2");
  script_cve_id("CVE-2017-16808", "CVE-2018-10103", "CVE-2018-10105", "CVE-2018-14461", "CVE-2018-14462", "CVE-2018-14463", "CVE-2018-14464", "CVE-2018-14465", "CVE-2018-14466", "CVE-2018-14467", "CVE-2018-14468", "CVE-2018-14469", "CVE-2018-14470", "CVE-2018-14879", "CVE-2018-14880", "CVE-2018-14881", "CVE-2018-14882", "CVE-2018-16227", "CVE-2018-16228", "CVE-2018-16229", "CVE-2018-16230", "CVE-2018-16300", "CVE-2018-16451", "CVE-2018-16452", "CVE-2018-19519", "CVE-2019-1010220", "CVE-2019-15166", "CVE-2019-15167");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-11 23:15:00 +0000 (Fri, 11 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4252-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4252-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4252-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tcpdump' package(s) announced via the USN-4252-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4252-1 fixed several vulnerabilities in tcpdump. This update provides
the corresponding update for Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.

Original advisory details:

 Multiple security issues were discovered in tcpdump. A remote attacker
 could use these issues to cause tcpdump to crash, resulting in a denial of
 service, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"tcpdump", ver:"4.9.3-0ubuntu0.12.04.1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"tcpdump", ver:"4.9.3-0ubuntu0.14.04.1+esm1", rls:"UBUNTU14.04 LTS"))) {
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
