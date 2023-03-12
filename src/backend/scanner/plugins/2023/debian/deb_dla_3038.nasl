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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2022.3038");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-3038");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3038");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2020/05/msg00011.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2021/12/msg00008.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2022/01/msg00015.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2022/04/msg00008.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2022/05/msg00060.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/debian-security-support");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'debian-security-support' package(s) announced via the DLA-3038 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"debian-security-support, the Debian security support coverage checker, has been updated in stretch-security to mark the end of life of the following packages:

* keystone: See [link moved to references] for further information.

* libspring-java: See [link moved to references] for further information.

* guacamole-client: See [link moved to references] for further information.

* gpac: See [link moved to references] for further information.

* ansible: Lack of an effective test suite makes proper support impossible.

* mysql-connector-java: Details of security vulnerabilities are not disclosed. MySQL has been replaced by MariaDB. We recommend to use mariadb-connector-java instead.

* ckeditor3: See [link moved to references] for further information.

For Debian 9 stretch, this problem has been fixed in version 1:9+2022.06.02.

We recommend that you upgrade your debian-security-support packages.

For the detailed security status of debian-security-support please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'debian-security-support' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"debian-security-support", ver:"1:9+2022.06.02", rls:"DEB9"))) {
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
