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
  script_oid("1.3.6.1.4.1.25623.1.0.819672");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2019-10734", "CVE-2020-15047");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-04 02:04:31 +0000 (Fri, 04 Feb 2022)");
  script_name("Fedora: Security Advisory for trojita (FEDORA-2022-7f67e9e695)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-7f67e9e695");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/UO27BOQW7OIOG56IBQEHPEIS5JYYKDHN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trojita'
  package(s) announced via the FEDORA-2022-7f67e9e695 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Trojit is a IMAP e-mail client which:

  * Enables you to access your mail anytime, anywhere.

  * Does not slow you down. If we can improve the productivity of an e-mail
    user, we better do.

  * Respects open standards and facilitates modern technologies. We value
    the vendor-neutrality that IMAP provides and are committed to be as
    inter-operable as possible.

  * Is efficient  be it at conserving the network bandwidth, keeping memory
    use at a reasonable level or not hogging the system&#39, s CPU.

  * Can be used on many platforms. One UI is not enough for everyone, but our
    IMAP core works fine on anything from desktop computers to cell phones
    and big ERP systems.

  * Plays well with the rest of the ecosystem. We don&#39, t like reinventing wheels,
    but when the existing wheels quite don&#39, t fit the tracks, we&#39, re not afraid
    of making them work.

This application is heavily based on Qt and uses WebKit.");

  script_tag(name:"affected", value:"'trojita' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"trojita", rpm:"trojita~0.7.0.1~0.13.20220117git266c757.fc35", rls:"FC35"))) {
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