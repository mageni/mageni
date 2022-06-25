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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2013.0283");
  script_cve_id("CVE-2013-4315");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-12-10 06:05:00 +0000 (Tue, 10 Dec 2013)");

  script_name("Mageia: Security Advisory (MGASA-2013-0283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA2");

  script_xref(name:"Advisory-ID", value:"MGASA-2013-0283");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2013-0283.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=11217");
  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2013/sep/10/security-releases-issued/");
  script_xref(name:"URL", value:"http://www.debian.org/security/2013/dsa-2755");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the MGASA-2013-0283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Rainer Koirikivi discovered a directory traversal vulnerability with
'ssi' template tags in python-django, a high-level Python web development
framework. It was shown that the handling of the 'ALLOWED_INCLUDE_ROOTS'
setting, used to represent allowed prefixes for the {% ssi %} template
tag, is vulnerable to a directory traversal attack, by specifying a file
path which begins as the absolute path of a directory in
'ALLOWED_INCLUDE_ROOTS', and then uses relative paths to break free. To
exploit this vulnerability an attacker must be in a position to alter
templates on the site, or the site to be attacked must have one or more
templates making use of the 'ssi' tag, and must allow some form of
unsanitized user input to be used as an argument to the 'ssi' tag
(CVE-2013-4315).");

  script_tag(name:"affected", value:"'python-django' package(s) on Mageia 2.");

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

if(release == "MAGEIA2") {

  if(!isnull(res = isrpmvuln(pkg:"python-django", rpm:"python-django~1.3.7~1.2.mga2", rls:"MAGEIA2"))) {
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
