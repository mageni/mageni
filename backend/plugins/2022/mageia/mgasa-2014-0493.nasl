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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0493");
  script_cve_id("CVE-2014-9031", "CVE-2014-9032", "CVE-2014-9033", "CVE-2014-9034", "CVE-2014-9035", "CVE-2014-9036", "CVE-2014-9037", "CVE-2014-9038", "CVE-2014-9039");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-11-02 18:11:00 +0000 (Mon, 02 Nov 2015)");

  script_name("Mageia: Security Advisory (MGASA-2014-0493)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0493");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0493.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=14625");
  script_xref(name:"URL", value:"https://wordpress.org/news/2014/11/wordpress-4-0-1/");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/11/25/12");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wordpress, wordpress' package(s) announced via the MGASA-2014-0493 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XSS in wptexturize() via comments or posts, exploitable for unauthenticated users (CVE-2014-9031).

XSS in media playlists (CVE-2014-9032).

CSRF in the password reset process (CVE-2014-9033).

Denial of service for giant passwords. The phpass library by Solar Designer
was used in both projects without setting a maximum password length, which
can lead to CPU exhaustion upon hashing (CVE-2014-9034).

XSS in Press This (CVE-2014-9035).

XSS in HTML filtering of CSS in posts (CVE-2014-9036).

Hash comparison vulnerability in old-style MD5-stored passwords
(CVE-2014-9037).

SSRF: Safe HTTP requests did not sufficiently block the loopback IP address
space (CVE-2014-9038).

Previously an email address change would not invalidate a previous password
reset email (CVE-2014-9039).");

  script_tag(name:"affected", value:"'wordpress, wordpress' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.9.3~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"wordpress", rpm:"wordpress~3.9.3~1.mga4", rls:"MAGEIA4"))) {
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
