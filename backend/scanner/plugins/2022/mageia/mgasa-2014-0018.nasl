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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0018");
  script_cve_id("CVE-2013-0179", "CVE-2013-7239", "CVE-2013-7290", "CVE-2013-7291");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-02-01T09:43:59+0000");
  script_tag(name:"last_modification", value:"2022-02-01 09:43:59 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-25 01:29:00 +0000 (Sun, 25 Mar 2018)");

  script_name("Mageia: Security Advisory (MGASA-2014-0018)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA3");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0018");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0018.html");
  script_xref(name:"URL", value:"http://www.debian.org/security/2014/dsa-2832");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12156");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'memcached' package(s) announced via the MGASA-2014-0018 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated memcached packages fix security vulnerability:

It was reported that SASL authentication could be bypassed due to a flaw
related to the management of the SASL authentication state. With a specially
crafted request, a remote attacker may be able to authenticate with invalid
SASL credentials (CVE-2013-7239).

Multiple issues in memcached before 1.4.17 which allow remote attackers to
cause a denial of service by sending a request that causes a crash when
memcached is running in verbose mode (CVE-2013-0179, CVE-2013-7290,
CVE-2013-7291).");

  script_tag(name:"affected", value:"'memcached' package(s) on Mageia 3.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"memcached", rpm:"memcached~1.4.17~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"memcached-devel", rpm:"memcached-devel~1.4.17~1.mga3", rls:"MAGEIA3"))) {
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
