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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.5482.2");
  script_cve_id("CVE-2020-28984", "CVE-2021-44118", "CVE-2021-44120", "CVE-2021-44122", "CVE-2021-44123", "CVE-2022-26846", "CVE-2022-26847");
  script_tag(name:"creation_date", value:"2023-03-03 04:37:35 +0000 (Fri, 03 Mar 2023)");
  script_version("2023-03-03T10:59:40+0000");
  script_tag(name:"last_modification", value:"2023-03-03 10:59:40 +0000 (Fri, 03 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-04 15:05:00 +0000 (Thu, 04 Feb 2021)");

  script_name("Ubuntu: Security Advisory (USN-5482-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5482-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5482-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'spip' package(s) announced via the USN-5482-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5482-1 fixed several vulnerabilities in SPIP. This update provides
the corresponding updates for Ubuntu 20.04 LTS for CVE-2021-44118,
CVE-2021-44120, CVE-2021-44122 and CVE-2021-44123.

Original advisory details:


 It was discovered that SPIP incorrectly validated inputs. An authenticated
 attacker could possibly use this issue to execute arbitrary code.
 This issue only affected Ubuntu 18.04 LTS. (CVE-2020-28984)

 Charles Fol and Theo Gordyjan discovered that SPIP is vulnerable to Cross
 Site Scripting (XSS). If a user were tricked into browsing a malicious SVG
 file, an attacker could possibly exploit this issue to execute arbitrary
 code. This issue was only fixed in Ubuntu 21.10. (CVE-2021-44118,
 CVE-2021-44120, CVE-2021-44122, CVE-2021-44123)

 It was discovered that SPIP incorrectly handled certain forms. A remote
 authenticated editor could possibly use this issue to execute arbitrary code,
 and a remote unauthenticated attacker could possibly use this issue to obtain
 sensitive information. (CVE-2022-26846, CVE-2022-26847)");

  script_tag(name:"affected", value:"'spip' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"spip", ver:"3.2.7-1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
