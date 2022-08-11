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
  script_oid("1.3.6.1.4.1.25623.1.0.819645");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2022-21658");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-04 02:04:32 +0000 (Fri, 04 Feb 2022)");
  script_name("Fedora: Security Advisory for rust-python-launcher (FEDORA-2022-7ec8bda833)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-7ec8bda833");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XC5M2E4TTPT5QBB7TN6PKGS6RRM3NOIM");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-python-launcher'
  package(s) announced via the FEDORA-2022-7ec8bda833 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Python Launcher for Unix.

Launch your Python interpreter the lazy/smart way!

This launcher is an implementation of the py command for Unix-based platforms.

The goal is to have py become the cross-platform command that Python users
typically use to launch an interpreter while doing development.
By having a command that is version-agnostic when it comes to Python,
it side-steps the 'what should the python command point to?' debate by clearly
specifying that upfront (i.e. the newest version of Python that can be found).
This also unifies the suggested command to document for launching Python on
both Windows as Unix as py has existed as the preferred command on Windows
since 2012 with the release of Python 3.3.

Typical usage would be:

    py -m venv .venv
    py ...  # Whatever you would normally use `python` for during development.

This creates a virtual environment in a .venv directory using the latest
version of Python installed. Subsequent uses of py will then use that virtual
environment as long as it is in the current (or higher) directory,
no environment activation required (although the Python Launcher supports
activated environments as well)!

A non-goal of this launcher is to become the way to launch the Python
interpreter all the time. If you know the exact interpreter you want to
launch then you should launch it directly, same goes for when you have
requirements on the type of interpreter you want.
The Python Launcher should be viewed as a tool of convenience, not necessity.");

  script_tag(name:"affected", value:"'rust-python-launcher' package(s) on Fedora 34.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-python-launcher", rpm:"rust-python-launcher~1.0.0~4.fc34", rls:"FC34"))) {
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