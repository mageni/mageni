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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2005.176.1");
  script_cve_id("CVE-2005-2494");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-176-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU5\.04");

  script_xref(name:"Advisory-ID", value:"USN-176-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-176-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kdebase' package(s) announced via the USN-176-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja van Sprundel discovered a flaw in the lock file handling of
kcheckpass. A local attacker could exploit this to execute arbitrary
code with root privileges.");

  script_tag(name:"affected", value:"'kdebase' package(s) on Ubuntu 5.04.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"kappfinder", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kate", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kcontrol", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-bin", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-data", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-dev", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-doc", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase-kio-plugins", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdebase", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdepasswd", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdeprint", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdesktop", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kdm", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kfind", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"khelpcenter", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kicker", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"klipper", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kmenuedit", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror-nsplugins", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konqueror", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"konsole", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpager", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kpersonalizer", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksmserver", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksplash", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksysguard", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ksysguardd", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ktip", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kwin", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkonq4-dev", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libkonq4", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfonts-konsole", ver:"3.4.0-0ubuntu18.1", rls:"UBUNTU5.04"))) {
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
