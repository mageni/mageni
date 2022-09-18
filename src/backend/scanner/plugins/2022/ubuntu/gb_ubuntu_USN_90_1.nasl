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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.90.1");
  script_cve_id("CVE-2005-0397");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-90-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU4\.10");

  script_xref(name:"Advisory-ID", value:"USN-90-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-90-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'imagemagick' package(s) announced via the USN-90-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered a format string vulnerability in ImageMagick's file
name handling. Specially crafted file names could cause a program using
ImageMagick to crash, or possibly even cause execution of arbitrary code.

Since ImageMagick can be used in custom printing systems, this also might lead
to privilege escalation (execute code with the printer spooler's privileges).
However, Ubuntu's standard printing system does not use ImageMagick, thus there
is no risk of privilege escalation in a standard installation.

ImageMagick is also commonly used by web frontends, if these accept image
uploads with arbitrary file names, this could also lead to remote privilege
escalation.");

  script_tag(name:"affected", value:"'imagemagick' package(s) on Ubuntu 4.10.");

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

if(release == "UBUNTU4.10") {

  if(!isnull(res = isdpkgvuln(pkg:"imagemagick", ver:"6.0.2.5-1ubuntu1.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++6-dev", ver:"6.0.2.5-1ubuntu1.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick++6", ver:"6.0.2.5-1ubuntu1.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick6-dev", ver:"6.0.2.5-1ubuntu1.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmagick6", ver:"6.0.2.5-1ubuntu1.4", rls:"UBUNTU4.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"perlmagick", ver:"6.0.2.5-1ubuntu1.4", rls:"UBUNTU4.10"))) {
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
