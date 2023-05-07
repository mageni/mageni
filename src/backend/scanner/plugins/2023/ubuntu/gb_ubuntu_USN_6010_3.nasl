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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6010.3");
  script_cve_id("CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536", "CVE-2023-29537", "CVE-2023-29538", "CVE-2023-29539", "CVE-2023-29540", "CVE-2023-29541", "CVE-2023-29543", "CVE-2023-29544", "CVE-2023-29547", "CVE-2023-29548", "CVE-2023-29549", "CVE-2023-29550", "CVE-2023-29551");
  script_tag(name:"creation_date", value:"2023-04-27 04:09:31 +0000 (Thu, 27 Apr 2023)");
  script_version("2023-04-27T12:17:38+0000");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-6010-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6010-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6010-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2017722");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6010-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6010-1 fixed vulnerabilities and USN-6010-2 fixed minor regressions in
Firefox. The update introduced several minor regressions. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2023-29537,
 CVE-2023-29540, CVE-2023-29543, CVE-2023-29544, CVE-2023-29547,
 CVE-2023-29548, CVE-2023-29549, CVE-2023-29550, CVE-2023-29551)

 Irvan Kurniawan discovered that Firefox did not properly manage fullscreen
 notifications using a combination of window.open, fullscreen requests,
 window.name assignments, and setInterval calls. An attacker could
 potentially exploit this issue to perform spoofing attacks. (CVE-2023-29533)

 Lukas Bernhard discovered that Firefox did not properly manage memory
 when doing Garbage Collector compaction. An attacker could potentially
 exploits this issue to cause a denial of service. (CVE-2023-29535)

 Zx from qriousec discovered that Firefox did not properly validate the
 address to free a pointer provided to the memory manager. An attacker could
 potentially exploits this issue to cause a denial of service.
 (CVE-2023-29536)

 Alexis aka zoracon discovered that Firefox did not properly validate the
 URI received by the WebExtension during a load request. An attacker could
 potentially exploits this to obtain sensitive information. (CVE-2023-29538)

 Trung Pham discovered that Firefox did not properly validate the filename
 directive in the Content-Disposition header. An attacker could possibly
 exploit this to perform reflected file download attacks potentially
 tricking users to install malware. (CVE-2023-29539)

 Ameen Basha M K discovered that Firefox did not properly validate downloads
 of files ending in .desktop. An attacker could potentially exploits this
 issue to execute arbitrary code. (CVE-2023-29541)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"112.0.2+build1-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"112.0.2+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
