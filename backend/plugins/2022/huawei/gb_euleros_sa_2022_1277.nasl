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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.1277");
  script_cve_id("CVE-2016-6893", "CVE-2021-42096", "CVE-2021-42097", "CVE-2021-44227");
  script_tag(name:"creation_date", value:"2022-03-02 03:24:15 +0000 (Wed, 02 Mar 2022)");
  script_version("2022-03-02T03:24:15+0000");
  script_tag(name:"last_modification", value:"2022-03-02 11:03:54 +0000 (Wed, 02 Mar 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");

  script_name("Huawei EulerOS: Security Advisory for mailman (EulerOS-SA-2022-1277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP5");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-1277");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1277");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'mailman' package(s) announced via the EulerOS-SA-2022-1277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site request forgery (CSRF) vulnerability in the user options page in GNU Mailman 2.1.x before 2.1.23 allows remote attackers to hijack the authentication of arbitrary users for requests that modify an option, as demonstrated by gaining access to the credentials of a victim's account.(CVE-2016-6893)

Sensitive information is exposed to unprivileged users in mailman. The hash of the list admin password is used to derive the CSRF (Cross-site Request Forgery) token, which is exposed to unprivileged members of a list. Malicious members may use the CSRF token to perform an offline brute-force attack to retrieve the list admin password.(CVE-2021-42096)

GNU Mailman before 2.1.35 may allow remote Privilege Escalation. A csrf_token value is not specific to a single user account. An attacker can obtain a value within the context of an unprivileged user account, and then use that value in a CSRF attack against an admin (e.g., for account takeover).(CVE-2021-42097)

In GNU Mailman before 2.1.38, a list member or moderator can get a CSRF token and craft an admin request (using that token) to set a new admin password or make other changes.(CVE-2021-44227)");

  script_tag(name:"affected", value:"'mailman' package(s) on Huawei EulerOS V2.0SP5.");

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

if(release == "EULEROS-2.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.15~26.1.h5.eulerosv2r7", rls:"EULEROS-2.0SP5"))) {
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
