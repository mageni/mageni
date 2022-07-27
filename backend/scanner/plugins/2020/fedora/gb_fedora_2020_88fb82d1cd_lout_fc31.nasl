# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.878545");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2019-19918", "CVE-2019-19917");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-10-31 04:14:15 +0000 (Sat, 31 Oct 2020)");
  script_name("Fedora: Security Advisory for lout (FEDORA-2020-88fb82d1cd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"FEDORA", value:"2020-88fb82d1cd");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5OXECUBSXEO7S3TCLSBCITLQIMOCL6MV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lout'
  package(s) announced via the FEDORA-2020-88fb82d1cd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lout is a document formatting system designed and implemented by Jeffrey
Kingston at the Basser Department of Computer Science, University of
Sydney, Australia. The system reads a high-level description of a document
similar in style to LaTeX and produces a PostScript file which can be
printed on most laser printers and graphic display devices. Plain text
output is also available, PDF output is limited but working (e.g. no
graphics). Lout is inherently multilingual. Adding new languages is easy.");

  script_tag(name:"affected", value:"'lout' package(s) on Fedora 31.");

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

  if(!isnull(res = isrpmvuln(pkg:"lout", rpm:"lout~3.40~18.fc31", rls:"FC31"))) {
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