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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5726.1");
  script_cve_id("CVE-2022-40674", "CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406", "CVE-2022-45407", "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410", "CVE-2022-45411", "CVE-2022-45412", "CVE-2022-45413", "CVE-2022-45415", "CVE-2022-45416", "CVE-2022-45417", "CVE-2022-45418", "CVE-2022-45419", "CVE-2022-45420", "CVE-2022-45421");
  script_tag(name:"creation_date", value:"2022-11-17 04:11:11 +0000 (Thu, 17 Nov 2022)");
  script_version("2022-11-17T04:11:11+0000");
  script_tag(name:"last_modification", value:"2022-11-17 04:11:11 +0000 (Thu, 17 Nov 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-16 03:09:00 +0000 (Fri, 16 Sep 2022)");

  script_name("Ubuntu: Security Advisory (USN-5726-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5726-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5726-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-5726-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were tricked
into opening a specially crafted website, an attacker could potentially
exploit these to cause a denial of service, spoof the contents of the
addressbar, bypass security restrictions, cross-site tracing or execute
arbitrary code. (CVE-2022-45403, CVE-2022-45404, CVE-2022-45405,
CVE-2022-45406, CVE-2022-45407, CVE-2022-45408, CVE-2022-45409, CVE-2022-45410,
CVE-2022-45411, CVE-2022-45413, CVE-2022-40674, CVE-2022-45418, CVE-2022-45419,
CVE-2022-45420, CVE-2022-45421)

Armin Ebert discovered that Firefox did not properly manage while resolving
file symlink. If a user were tricked into opening a specially crafted weblink,
an attacker could potentially exploit these to cause a denial of service.
(CVE-2022-45412)

Jefferson Scher and Jayateertha Guruprasad discovered that Firefox did not
properly sanitize the HTML download file extension under certain circumstances.
If a user were tricked into downloading and executing malicious content, a
remote attacker could execute arbitrary code with the privileges of the user
invoking the programs. (CVE-2022-45415)

Erik Kraft, Martin Schwarzl, and Andrew McCreight discovered that Firefox
incorrectly handled keyboard events. An attacker could possibly use this
issue to perform a timing side-channel attack and possibly figure out which
keys are being pressed. (CVE-2022-45416)

Kagami discovered that Firefox did not detect Private Browsing Mode correctly.
An attacker could possibly use this issue to obtain sensitive information about
Private Browsing Mode.
(CVE-2022-45417)");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"107.0+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"107.0+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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
