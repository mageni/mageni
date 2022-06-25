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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0163");
  script_cve_id("CVE-2015-1821", "CVE-2015-1822", "CVE-2015-1853");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-17 17:52:00 +0000 (Tue, 17 Dec 2019)");

  script_name("Mageia: Security Advisory (MGASA-2015-0163)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0163");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0163.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15647");
  script_xref(name:"URL", value:"http://chrony.tuxfamily.org/News.html");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3222");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chrony' package(s) announced via the MGASA-2015-0163 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chrony package fixes security vulnerabilities:

Using particular address/subnet pairs when configuring access control would
cause an invalid memory write. This could allow attackers to cause a denial
of service (crash) or execute arbitrary code (CVE-2015-1821).

When allocating memory to save unacknowledged replies to authenticated
command requests, a pointer would be left uninitialized, which could trigger
an invalid memory write. This could allow attackers to cause a denial of
service (crash) or execute arbitrary code (CVE-2015-1822).

When peering with other NTP hosts using authenticated symmetric association,
the internal state variables would be updated before the MAC of the NTP
messages was validated. This could allow a remote attacker to cause a denial
of service by impeding synchronization between NTP peers (CVE-2015-1853).");

  script_tag(name:"affected", value:"'chrony' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"chrony", rpm:"chrony~1.29.1~1.1.mga4", rls:"MAGEIA4"))) {
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
