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
  script_oid("1.3.6.1.4.1.25623.1.0.822888");
  script_version("2022-11-25T10:12:49+0000");
  script_cve_id("CVE-2022-42919");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-25 10:12:49 +0000 (Fri, 25 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-23 02:18:21 +0000 (Wed, 23 Nov 2022)");
  script_name("Fedora: Security Advisory for python3.10 (FEDORA-2022-a7cad6bd22)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-a7cad6bd22");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XX6LLAXGZVZ327REY6MDZRMMP47LJ53P");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.10'
  package(s) announced via the FEDORA-2022-a7cad6bd22 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.10 is an accessible, high-level, dynamically typed, interpreted
programming language, designed with an emphasis on code readability.
It includes an extensive standard library, and has a vast ecosystem of
third-party libraries.

The python3.10 package provides the 'python3.10' executable: the reference
interpreter for the Python language, version 3.
The majority of its standard library is provided in the python3.10-libs package,
which should be installed automatically along with python3.10.
The remaining parts of the Python standard library are broken out into the
python3.10-tkinter and python3.10-test packages, which may need to be installed
separately.

Documentation for Python is provided in the python3.10-docs package.

Packages containing additional libraries for Python are generally named with
the 'python3.10-' prefix.");

  script_tag(name:"affected", value:"'python3.10' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"python3.10", rpm:"python3.10~3.10.8~3.fc37", rls:"FC37"))) {
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