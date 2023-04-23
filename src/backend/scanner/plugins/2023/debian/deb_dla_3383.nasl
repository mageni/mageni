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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3383");
  script_cve_id("CVE-2022-1537");
  script_tag(name:"creation_date", value:"2023-04-06 04:25:19 +0000 (Thu, 06 Apr 2023)");
  script_version("2023-04-06T10:08:49+0000");
  script_tag(name:"last_modification", value:"2023-04-06 10:08:49 +0000 (Thu, 06 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-16 17:08:00 +0000 (Mon, 16 May 2022)");

  script_name("Debian: Security Advisory (DLA-3383)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3383");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3383");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'grunt' package(s) announced via the DLA-3383 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential local privilege escalation in GruntJS, a multipurpose task runner and build system tool.

file.copy operations in GruntJS were vulnerable to a TOCTOU ('time-of-check vs. time-of-use') race condition that could have led to arbitrary file writes in GitHub repositories. This could have then led to local privilege escalation if a lower-privileged user had write access to both source and destination directories, as the lower-privileged user could have created a symlink to the GruntJS user's ~/.bashrc configuration file (etc).

CVE-2022-1537

file.copy operations in GruntJS are vulnerable to a TOCTOU race condition leading to arbitrary file write in GitHub repository gruntjs/grunt prior to 1.5.3. This vulnerability is capable of arbitrary file writes which can lead to local privilege escalation to the GruntJS user if a lower-privileged user has write access to both source and destination directories as the lower-privileged user can create a symlink to the GruntJS user's .bashrc file or replace /etc/shadow file if the GruntJS user is root.

For Debian 10 Buster, this problem has been fixed in version 1.0.1-8+deb10u2.

We recommend that you upgrade your grunt packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'grunt' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"grunt", ver:"1.0.1-8+deb10u2", rls:"DEB10"))) {
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
