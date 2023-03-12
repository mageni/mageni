# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2015.298");
  script_cve_id("CVE-2012-6130", "CVE-2012-6131", "CVE-2012-6132", "CVE-2012-6133");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 20:48:00 +0000 (Fri, 31 Jan 2020)");

  script_name("Debian: Security Advisory (DLA-298)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-298");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2015/dla-298");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'roundup' package(s) announced via the DLA-298 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2012-6130

Cross-site scripting (XSS) vulnerability in the history display in Roundup before 1.4.20 allows remote attackers to inject arbitrary web script or HTML via a username, related to generating a link.

CVE-2012-6131

Cross-site scripting (XSS) vulnerability in cgi/client.py in Roundup before 1.4.20 allows remote attackers to inject arbitrary web script or HTML via the @action parameter to support/issue1.

CVE-2012-6132

Cross-site scripting (XSS) vulnerability in Roundup before 1.4.20 allows remote attackers to inject arbitrary web script or HTML via the otk parameter.

CVE-2012-6133

XSS flaws in ok and error messages We solve this differently from the proposals in the bug-report by not allowing *any* html-tags in ok/error messages anymore.");

  script_tag(name:"affected", value:"'roundup' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"roundup", ver:"1.4.15-3+deb6u1", rls:"DEB6"))) {
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
