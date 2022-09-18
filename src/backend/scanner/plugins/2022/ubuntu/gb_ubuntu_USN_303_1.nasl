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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.303.1");
  script_cve_id("CVE-2006-2753");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-303-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-303-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mysql-dfsg-4.1, mysql-dfsg-5.0' package(s) announced via the USN-303-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An SQL injection vulnerability has been discovered when using less
popular multibyte encodings (such as SJIS, or BIG5) which contain
valid multibyte characters that end with the byte 0x5c (the
representation of the backslash character >>\<< in ASCII).

Many client libraries and applications use the non-standard, but
popular way of escaping the >>'<< character by replacing all
occurrences of it with >>\'<<. If a client application uses one of the
affected encodings and does not interpret multibyte characters, and an
attacker supplies a specially crafted byte sequence as an input string
parameter, this escaping method would then produce a validly-encoded
character and an excess >>'<< character which would end the string.
All subsequent characters would then be interpreted as SQL code, so
the attacker could execute arbitrary SQL commands.

The updated packages fix the mysql_real_escape_string() function to
escape quote characters in a safe way. If you use third-party software
which uses an ad-hoc method of string escaping, you should convert
them to use mysql_real_escape_string() instead, or at least use the
standard SQL method of escaping >>'<< with >>''<<.");

  script_tag(name:"affected", value:"'mysql-dfsg-4.1, mysql-dfsg-5.0' package(s) on Ubuntu 5.10, Ubuntu 6.06.");

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

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient14", ver:"4.1.12-1ubuntu3.5", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-4.1", ver:"4.1.12-1ubuntu3.5", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libmysqlclient15off", ver:"5.0.22-0ubuntu6.06", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mysql-server-5.0", ver:"5.0.22-0ubuntu6.06", rls:"UBUNTU6.06 LTS"))) {
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
