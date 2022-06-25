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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0180");
  script_cve_id("CVE-2013-5123");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 19:51:00 +0000 (Tue, 12 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2015-0180)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0180");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0180.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15748");
  script_xref(name:"URL", value:"https://pip.pypa.io/en/latest/news.html");
  script_xref(name:"URL", value:"http://advisories.mageia.org/MGASA-2015-0120.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-April/155248.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip, python-virtualenv' package(s) announced via the MGASA-2015-0180 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-pip and python-virtualenv packages fix security vulnerability:

The mirroring support in python-pip was implemented without any sort of
authenticity checks and is downloaded over plaintext HTTP. Further more by
default it will dynamically discover the list of available mirrors by
querying a DNS entry and extrapolating from that data. It does not attempt
to use any sort of method of securing this querying of the DNS like DNSSEC.
Software packages are downloaded over these insecure links, unpacked, and
then typically the setup.py python file inside of them is executed
(CVE-2013-5123).

This was fixed in python-pip by removing the mirroring support (i.e., the
--use-mirrors, -M, and --mirrors flags). With the updated version, in order
to use a mirror, one must specify it as the primary index with -i or
--index-url, or as an additional index with --extra-index-url.

The python-virtualenv package bundles a copy of python-pip, so it has also
been updated to fix this issue.

The python-virtualenv package bundles python-requests as well, so this update
fixes the session fixation issue CVE-2015-2296 in the bundled python-requests.");

  script_tag(name:"affected", value:"'python-pip, python-virtualenv' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~6.1.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-virtualenv", rpm:"python-virtualenv~12.1.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~6.1.1~1.mga4", rls:"MAGEIA4"))) {
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
