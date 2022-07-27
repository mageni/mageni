# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.843977");
  script_version("2019-04-19T05:29:08+0000");
  script_cve_id("CVE-2019-11070", "CVE-2019-6251", "CVE-2019-8375", "CVE-2019-8506",
                "CVE-2019-8518", "CVE-2019-8523", "CVE-2019-8524", "CVE-2019-8535",
                "CVE-2019-8536", "CVE-2019-8544", "CVE-2019-8551", "CVE-2019-8558",
                "CVE-2019-8559", "CVE-2019-8563");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-19 05:29:08 +0000 (Fri, 19 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-17 02:00:36 +0000 (Wed, 17 Apr 2019)");
  script_name("Ubuntu Update for webkit2gtk USN-3948-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.04 LTS|UBUNTU18\.10)");

  script_xref(name:"URL", value:"http://www.ubuntu.com/usn/usn-3948-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for
  the 'webkit2gtk' package(s) announced via the USN-3948-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version
  is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were
discovered in the WebKitGTK+ Web and JavaScript engines. If a user were tricked
into viewing a malicious website, a remote attacker could exploit a variety of
issues related to web browser security, including cross-site scripting attacks,
denial of service attacks, and arbitrary code execution.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.24.1-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.24.1-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.24.1-0ubuntu0.18.10.2", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.24.1-0ubuntu0.18.10.2", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
