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
  script_oid("1.3.6.1.4.1.25623.1.0.819527");
  script_version("2022-01-14T07:06:50+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-01-14 11:23:55 +0000 (Fri, 14 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-14 02:01:52 +0000 (Fri, 14 Jan 2022)");
  script_name("Fedora: Security Advisory for e00compr (FEDORA-2022-6179b789ea)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-6179b789ea");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TJTJXR3S6TCNB5LOVMDZAYUR2DYBECLK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'e00compr'
  package(s) announced via the FEDORA-2022-6179b789ea advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"E00compr is an ANSI C library that reads and writes Arc/Info compressed E00
files. Both PARTIAL and FULL compression levels are supported.

This package can be divided in three parts:

   The e00conv command-line program. This program takes a E00 file as input
    (compressed or not) and copies it to a new file with the requested
    compression level (NONE, PARTIAL or FULL).

   A set of library functions to read compressed E00 files. These functions
    read a E00 file (compressed or not) and return a stream of uncompressed
    lines, making the E00 file appear as if it was not compressed.

   A set of library functions to write compressed E00 files. These functions
    take one line after another from what should be a uncompressed E00 file,
    and write them to a file with the requested compression level, either NONE,
    PARTIAL or FULL.

This is a metapackage that installs both the command-line tools
(e00compr-tools) and the libraries (e00compr-libs).");

  script_tag(name:"affected", value:"'e00compr' package(s) on Fedora 34.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"e00compr", rpm:"e00compr~1.0.1~28.fc34", rls:"FC34"))) {
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