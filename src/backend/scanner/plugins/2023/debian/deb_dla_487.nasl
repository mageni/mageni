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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.487");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-487)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-487");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-487");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2015/08/msg00035.html");
  script_xref(name:"URL", value:"https://www.debian.org/releases/jessie/amd64/release-notes/ch-information.html#mediawiki-security");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2016/05/msg00197.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts/2015/11/msg00049.html");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'debian-security-support' package(s) announced via the DLA-487 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Debian Long Term Support (LTS) Team is unable to continue supporting different packages in the extended life cycle of Wheezy LTS. The debian-security-support package provides the check-support-status tool that helps to warn the administrator about installed packages whose security support is limited or has to prematurely end.

debian-security-support version 2016.05.24~deb7u1 updates the list of packages with restricted support in Wheezy LTS, adding the following:

Source Package Last supported version EOL date Additional information

libv8 3.8.9.20-2 2016-02-06 [link moved to references]

mediawiki 1:1.19.20+dfsg-0+deb7u32016-04-26 [link moved to references]

sogo 1.3.16-1 2016-05-19 [link moved to references]

vlc 2.0.3-5+deb7u2 2016-02-06 [link moved to references]

If you rely on those packages on a system running Debian 7 Wheezy, we recommend you to upgrade to Debian 8 Jessie, the current stable release. Note however that the mediawiki support has also ended in Jessie.

We recommend you to install the debian-security-support package to verify the support status of the packages installed on the system.

More information about Debian LTS can be found at: [link moved to references]

For Debian 7 Wheezy, these issues have been fixed in debian-security-support version 2016.05.24~deb7u1");

  script_tag(name:"affected", value:"'debian-security-support' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"debian-security-support", ver:"2016.05.24~deb7u1", rls:"DEB7"))) {
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
