# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.875670");
  script_version("2019-05-14T05:04:40+0000");
  script_cve_id("CVE-2016-4463", "CVE-2017-12627");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-14 05:04:40 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-07 02:15:16 +0000 (Tue, 07 May 2019)");
  script_name("Fedora Update for xerces-c27 FEDORA-2018-51ce232320");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MMCXOMXMDGI3E4QPKT555STPNMAXVYFN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-c27'
  package(s) announced via the FEDORA-2018-51ce232320 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xerces-C is a validating XML parser written in a portable subset of C++.
Xerces-C makes it easy to give your application the ability to read and write
XML data. A shared library is provided for parsing, generating, manipulating,
and validating XML documents. Xerces-C is faithful to the XML 1.0
recommendation and associated standards ( DOM 1.0, DOM 2.0. SAX 1.0, SAX 2.0,
Namespaces).

Note that this package contains Xerces-C++ 2.7.0 for compatibility with
applications that cannot use a newer version.");

  script_tag(name:"affected", value:"'xerces-c27' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"xerces-c27", rpm:"xerces-c27~2.7.0~28.fc29", rls:"FC29"))) {
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
