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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0138");
  script_cve_id("CVE-2021-43980", "CVE-2022-23181", "CVE-2022-29885", "CVE-2022-34305", "CVE-2022-42252", "CVE-2022-45143", "CVE-2023-24998", "CVE-2023-28708");
  script_tag(name:"creation_date", value:"2023-04-17 04:13:02 +0000 (Mon, 17 Apr 2023)");
  script_version("2023-04-17T10:09:22+0000");
  script_tag(name:"last_modification", value:"2023-04-17 10:09:22 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-01 15:09:00 +0000 (Wed, 01 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0138)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0138");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0138.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30113");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010339.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-April/010734.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.65");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.62");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3160");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5265");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.68");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.69");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.71");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-March/014018.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.72");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat' package(s) announced via the MGASA-2023-0138 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Information disclosure due to concurrency bug (CVE-2021-43980)
Fix for CVE-2020-9484 introduced a time of check, time of use
vulnerability (CVE-2022-23181)
Correct documentation to warn of use over untrusted networks.
(CVE-2022-29885)
Correct documentation showing use of XSS vulnerability. (CVE-2022-34305)
Fix to reject invalid Content-Length header (CVE-2022-42252)
Fix escaping of the type, message or description values. (CVE-2022-45143)
Fix FileUpload limiting of the number of request parts to be processed
to prevent the possibility of an attacker triggering a DoS (CVE-2023-24998)
Fix setting of session cookie secure attribute when using RemoteIpFilter
with X-Forwarded-Proto header set to https (CVE-2023-28708)
Obsolete tomcat-jsvc");

  script_tag(name:"affected", value:"'tomcat' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat", rpm:"tomcat~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-admin-webapps", rpm:"tomcat-admin-webapps~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-docs-webapp", rpm:"tomcat-docs-webapp~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-el-3.0-api", rpm:"tomcat-el-3.0-api~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-jsp-2.3-api", rpm:"tomcat-jsp-2.3-api~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-lib", rpm:"tomcat-lib~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-servlet-4.0-api", rpm:"tomcat-servlet-4.0-api~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tomcat-webapps", rpm:"tomcat-webapps~9.0.73~1.1.mga8", rls:"MAGEIA8"))) {
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
