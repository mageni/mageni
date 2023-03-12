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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2018.1606");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-1606)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1606");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1606");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gcc-4.9' package(s) announced via the DLA-1606 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes libstdc++ std::future support on armel, which is necessary to get firefox-esr and thunderbird updates built on that architecture.

For Debian 8 Jessie, this problem has been fixed in version 4.9.2-10+deb8u2.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'gcc-4.9' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"cpp-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fixincludes", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"g++-4.9-multilib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"g++-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcc-4.9-base", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcc-4.9-locales", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcc-4.9-multilib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcc-4.9-plugin-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcc-4.9-source", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcc-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gccgo-4.9-multilib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gccgo-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcj-4.9-jdk", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcj-4.9-jre-headless", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcj-4.9-jre-lib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcj-4.9-jre", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcj-4.9-source", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gcj-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gdc-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gfortran-4.9-multilib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gfortran-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gobjc++-4.9-multilib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gobjc++-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gobjc-4.9-multilib", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gobjc-4.9", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32asan1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32asan1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32atomic1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32atomic1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32cilkrts5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32cilkrts5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gcc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gcc1-dbg", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gcc1", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gfortran-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gfortran3-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gfortran3", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32go5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32go5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gomp1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32gomp1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32itm1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32itm1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32lsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32lsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32objc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32objc4-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32objc4", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32quadmath0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32quadmath0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32stdc++-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32stdc++6-4.9-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32stdc++6", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32ubsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32ubsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64asan1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64asan1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64atomic1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64atomic1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64cilkrts5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64cilkrts5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gcc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gcc1-dbg", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gcc1", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gfortran-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gfortran3-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gfortran3", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64go5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64go5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gomp1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64gomp1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64itm1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64itm1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64objc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64objc4-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64objc4", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64quadmath0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64quadmath0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64stdc++-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64stdc++6-4.9-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64stdc++6", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ubsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ubsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasan1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libasan1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libatomic1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libatomic1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcilkrts5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcilkrts5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcc1-dbg", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcc1", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcj-doc", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcj15-awt", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcj15-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcj15-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgcj15", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgfortran-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgfortran3-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgfortran3", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgo5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgo5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgomp1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgomp1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libitm1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libitm1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"liblsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libobjc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libobjc4-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libobjc4", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libphobos-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libquadmath0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libquadmath0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstdc++-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstdc++-4.9-doc", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstdc++-4.9-pic", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstdc++6-4.9-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstdc++6", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libubsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libubsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32asan1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32asan1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32atomic1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32atomic1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32cilkrts5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32cilkrts5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gcc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gcc1-dbg", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gcc1", ver:"1:4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gfortran-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gfortran3-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gfortran3", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32go5-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32go5", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gomp1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32gomp1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32itm1-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32itm1", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32lsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32lsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32objc-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32objc4-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32objc4", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32quadmath0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32quadmath0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32stdc++-4.9-dev", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32stdc++6-4.9-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32stdc++6", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32ubsan0-dbg", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libx32ubsan0", ver:"4.9.2-10+deb8u2", rls:"DEB8"))) {
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
