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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0220");
  script_cve_id("CVE-2020-11033", "CVE-2020-11034", "CVE-2020-11035", "CVE-2020-11036");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-15 05:15:00 +0000 (Fri, 15 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0220)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0220");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0220.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26625");
  script_xref(name:"URL", value:"https://github.com/glpi-project/glpi/security/advisories/GHSA-rf54-3r4w-4h55");
  script_xref(name:"URL", value:"https://github.com/glpi-project/glpi/security/advisories/GHSA-gxv6-xq9q-37hg");
  script_xref(name:"URL", value:"https://github.com/glpi-project/glpi/security/advisories/GHSA-w7q8-58qp-vmpf");
  script_xref(name:"URL", value:"https://github.com/glpi-project/glpi/security/advisories/GHSA-3g3h-rwhr-7385");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/Q4BG2UTINBVV7MTJRXKBQ26GV2UINA6L/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glpi' package(s) announced via the MGASA-2020-0220 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated glpi packages fix security vulnerabilities:

In GLPI from version 9.1 and before version 9.4.6, any API user with READ
right on User itemtype will have access to full list of users when querying
apirest.php/User. The response contains: - All api_tokens which can be used
to do privileges escalations or read/update/delete data normally non
accessible to the current user. - All personal_tokens can display another
users planning. Exploiting this vulnerability requires the api to be
enabled, a technician account. It can be mitigated by adding an application
token (CVE-2020-11033).

In GLPI before version 9.4.6, there is a vulnerability that allows
bypassing the open redirect protection based which is based on a regexp
(CVE-2020-11034).

In GLPI after version 0.83.3 and before version 9.4.6, the CSRF tokens are
generated using an insecure algorithm. The implementation uses rand and
uniqid and MD5 which does not provide secure values (CVE-2020-11035).

In GLPI before version 9.4.6 there are multiple related stored XSS
vulnerabilities. The package is vulnerable to Stored XSS in the comments of
items in the Knowledge base. Adding a comment with content '<script>alert(1)
</script>' reproduces the attack. This can be exploited by a user with
administrator privileges in the User-Agent field. It can also be exploited
by an outside party through the following steps: 1. Create a user with the
surname `' onmouseover='alert(document.cookie)` and an empty first name. 2.
With this user, create a ticket 3. As an administrator (or other privileged
user) open the created ticket 4. On the 'last update' field, put your mouse
on the name of the user 5. The XSS fires (CVE-2020-11036).");

  script_tag(name:"affected", value:"'glpi' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"glpi", rpm:"glpi~9.4.5~1.2.mga7", rls:"MAGEIA7"))) {
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
