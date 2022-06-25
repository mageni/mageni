# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.879769");
  script_version("2021-07-07T08:21:00+0000");
  script_cve_id("CVE-2021-32677");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-07-07 08:21:00 +0000 (Wed, 07 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-06-20 03:17:01 +0000 (Sun, 20 Jun 2021)");
  script_name("Fedora: Security Advisory for python-fastapi (FEDORA-2021-917e89c036)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-917e89c036");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MATAWX25TYKNEKLDMKWNLYDB34UWTROA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-fastapi'
  package(s) announced via the FEDORA-2021-917e89c036 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FastAPI is a modern, fast (high-performance), web framework for building APIs
with Python 3.6+ based on standard Python type hints.

The key features are:

   Fast: Very high performance, on par with NodeJS and Go (thanks to Starlette
    and Pydantic). One of the fastest Python frameworks available.

   Fast to code: Increase the speed to develop features by about 200% to 300%.*
   Fewer bugs: Reduce about 40% of human (developer) induced errors.*
   Intuitive: Great editor support. Completion everywhere. Less time
    debugging.
   Easy: Designed to be easy to use and learn. Less time reading docs.
   Short: Minimize code duplication. Multiple features from each parameter
    declaration. Fewer bugs.
   Robust: Get production-ready code. With automatic interactive
    documentation.
   Standards-based: Based on (and fully compatible with) the open standards
    for APIs: OpenAPI (previously known as Swagger) and JSON Schema.

  * estimation based on tests on an internal development team, building production
  applications.");

  script_tag(name:"affected", value:"'python-fastapi' package(s) on Fedora 34.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-fastapi", rpm:"python-fastapi~0.65.2~1.fc34", rls:"FC34"))) {
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