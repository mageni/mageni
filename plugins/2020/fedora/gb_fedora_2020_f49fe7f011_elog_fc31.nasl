# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.877388");
  script_version("2020-01-28T10:45:23+0000");
  script_cve_id("CVE-2019-3993", "CVE-2019-3994", "CVE-2019-3995", "CVE-2019-3992", "CVE-2019-3996");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-28 10:45:23 +0000 (Tue, 28 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 09:25:46 +0000 (Mon, 27 Jan 2020)");
  script_name("Fedora: Security Advisory for elog (FEDORA-2020-f49fe7f011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4IAS4HI24H2ERKBZTDEVJ3LEQEFWYSCT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'elog'
  package(s) announced via the FEDORA-2020-f49fe7f011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ELOG is part of a family of applications known as weblogs. Their general
purpose is:

1. To make it easy for people to put information online in a chronological
fashion, in the form of short, time-stamped text messages ('entries') with
optional HTML markup for presentation, and optional file attachments
(images, archives, etc.)

2. To make it easy for other people to access this information through a
Web interface, browse entries, search, download files, and optionally add,
update, delete or comment on entries.

ELOG is a remarkable implementation of a weblog in at least two respects:

1. Its simplicity of use: you don&#39, t need to be a seasoned server operator
and/or an experimented database administrator to run ELOG, one executable
file (under Unix or Windows), a simple configuration text file, and it works.
No Web server or relational database required. It is also easy to translate
the interface to the appropriate language for your users.

2. Its versatility: through its single configuration file, ELOG can be made
to display an infinity of variants of the weblog concept. There are options
for what to display, how to display it, what commands are available and to
whom, access control, etc. Moreover, a single server can host several
weblogs, and each weblog can be totally different from the rest.");

  script_tag(name:"affected", value:"'elog' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"elog", rpm:"elog~3.1.4~1.20190113git283534d97d5a.fc31", rls:"FC31"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);