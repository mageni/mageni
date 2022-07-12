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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0566");
  script_cve_id("CVE-2021-45046");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-21 00:15:00 +0000 (Tue, 21 Dec 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0566)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0566");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0566.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29766");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2021/12/14/4");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-7rjr-3q55-vv33");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'log4j' package(s) announced via the MGASA-2021-0566 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0
was incomplete in certain non-default configurations. This could allows
attackers with control over Thread Context Map (MDC) input data when the
logging configuration uses a non-default Pattern Layout with either a
Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map
pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI
Lookup pattern resulting in a denial of service (DOS) attack. Log4j 2.15.0
makes a best-effort attempt to restrict JNDI LDAP lookups to localhost by
default. Log4j 2.16.0 fixes this issue by removing support for message
lookup patterns and disabling JNDI functionality by default
(CVE-2021-45046).");

  script_tag(name:"affected", value:"'log4j' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"log4j", rpm:"log4j~2.16.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-jcl", rpm:"log4j-jcl~2.16.0~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"log4j-slf4j", rpm:"log4j-slf4j~2.16.0~1.mga8", rls:"MAGEIA8"))) {
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
