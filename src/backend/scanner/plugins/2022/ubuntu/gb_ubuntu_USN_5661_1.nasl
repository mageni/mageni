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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2022.5661.1");
  script_cve_id("CVE-2022-26305", "CVE-2022-26306", "CVE-2022-26307");
  script_tag(name:"creation_date", value:"2022-10-07 04:30:33 +0000 (Fri, 07 Oct 2022)");
  script_version("2022-10-07T10:12:53+0000");
  script_tag(name:"last_modification", value:"2022-10-07 10:12:53 +0000 (Fri, 07 Oct 2022)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-02 13:39:00 +0000 (Tue, 02 Aug 2022)");

  script_name("Ubuntu: Security Advisory (USN-5661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5661-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5661-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the USN-5661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that LibreOffice incorrectly validated macro signatures.
If a user were tricked into opening a specially crafted document, a remote
attacker could possibly use this issue to execute arbitrary macros.
(CVE-2022-26305)

It was discovered that Libreoffice incorrectly handled encrypting the
master key provided by the user for storing passwords for web connections.
A local attacker could possibly use this issue to obtain access to
passwords stored in the user's configuration data. (CVE-2022-26306,
CVE-2022-26307)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libreoffice", ver:"1:6.4.7-0ubuntu0.20.04.5", rls:"UBUNTU20.04 LTS"))) {
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
