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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5680.1");
  script_cve_id("CVE-2019-20326", "CVE-2020-36427");
  script_tag(name:"creation_date", value:"2022-10-17 04:52:15 +0000 (Mon, 17 Oct 2022)");
  script_version("2022-10-17T11:13:19+0000");
  script_tag(name:"last_modification", value:"2022-10-17 11:13:19 +0000 (Mon, 17 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-09 21:45:00 +0000 (Mon, 09 Nov 2020)");

  script_name("Ubuntu: Security Advisory (USN-5680-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5680-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5680-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gthumb' package(s) announced via the USN-5680-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that gThumb did not properly managed
memory when processing certain image files. If a user were
tricked into opening a specially crafted JPEG file, an
attacker could possibly use this issue to cause gThumb to
crash, resulting in a denial of service, or possibly
execute arbitrary code. (CVE-2019-20326)

It was discovered that gThumb did not properly handled
certain malformed image files. If a user were tricked into
opening a specially crafted JPEG file, an attacker could
possibly use this issue to cause gThumb to crash, resulting
in a denial of service. (CVE-2020-36427)");

  script_tag(name:"affected", value:"'gthumb' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gthumb-data", ver:"3:3.8.0-2.1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gthumb", ver:"3:3.8.0-2.1ubuntu0.1", rls:"UBUNTU20.04 LTS"))) {
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
