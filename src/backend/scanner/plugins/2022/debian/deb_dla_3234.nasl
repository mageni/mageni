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
  script_oid("1.3.6.1.4.1.25623.1.0.893234");
  script_version("2022-12-13T10:10:56+0000");
  script_cve_id("CVE-2022-41853");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-11 02:00:14 +0000 (Sun, 11 Dec 2022)");
  script_name("Debian LTS: Security Advisory for hsqldb (DLA-3234-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3234-1");
  script_xref(name:"Advisory-ID", value:"DLA-3234-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1023573");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hsqldb'
  package(s) announced via the DLA-3234-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that those using java.sql.Statement or java.sql.PreparedStatement
in hsqldb, a Java SQL database, to process untrusted input may be vulnerable to
a remote code execution attack. By default it is allowed to call any static
method of any Java class in the classpath resulting in code execution. The
issue can be prevented by updating to 2.4.1-2+deb10u1 or by setting the
system property 'hsqldb.method_class_names' to classes which are allowed to
be called. For example, System.setProperty('hsqldb.method_class_names','abc')
or Java argument -Dhsqldb.method_class_names='abc' can be used. From
version 2.4.1-2+deb10u1 all classes by default are not accessible except
those in java.lang.Math and need to be manually enabled.");

  script_tag(name:"affected", value:"'hsqldb' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
2.4.1-2+deb10u1.

We recommend that you upgrade your hsqldb packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hsqldb-utils", ver:"2.4.1-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhsqldb-java", ver:"2.4.1-2+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libhsqldb-java-doc", ver:"2.4.1-2+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
