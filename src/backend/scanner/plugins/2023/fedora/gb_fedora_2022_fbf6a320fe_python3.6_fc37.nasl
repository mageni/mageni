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
  script_oid("1.3.6.1.4.1.25623.1.0.823095");
  script_version("2023-01-09T10:12:48+0000");
  script_cve_id("CVE-2022-45061");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-09 10:12:48 +0000 (Mon, 09 Jan 2023)");
  script_tag(name:"creation_date", value:"2022-12-30 02:14:06 +0000 (Fri, 30 Dec 2022)");
  script_name("Fedora: Security Advisory for python3.6 (FEDORA-2022-fbf6a320fe)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-fbf6a320fe");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UHVW73QZJMHA4MK7JBT7CXX7XSNYQEGF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.6'
  package(s) announced via the FEDORA-2022-fbf6a320fe advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Python 3.6 package for developers.

This package exists to allow developers to test their code against an older
version of Python. This is not a full Python stack and if you wish to run
your applications with Python 3.6, see other distributions
that support it, such as CentOS or RHEL with Software Collections
or older Fedora releases.");

  script_tag(name:"affected", value:"'python3.6' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.6", rpm:"python3.6~3.6.15~15.fc37", rls:"FC37"))) {
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