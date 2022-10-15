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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0369");
  script_cve_id("CVE-2022-37797", "CVE-2022-41556");
  script_tag(name:"creation_date", value:"2022-10-14 04:46:38 +0000 (Fri, 14 Oct 2022)");
  script_version("2022-10-14T04:46:38+0000");
  script_tag(name:"last_modification", value:"2022-10-14 04:46:38 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 19:38:00 +0000 (Fri, 07 Oct 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0369");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0369.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30912");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5243");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'lighttpd' package(s) announced via the MGASA-2022-0369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In lighttpd 1.4.65, mod_wstunnel does not initialize a handler function
pointer if an invalid HTTP request (websocket handshake) is received. It
leads to null pointer dereference which crashes the server. It could be
used by an external attacker to cause denial of service condition.
(CVE-2022-37797)

A resource leak in mod_fastcgi and mod_scgi could lead to a denial of
service after a large number of bad HTTP requests. (CVE-2022-41556)");

  script_tag(name:"affected", value:"'lighttpd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lighttpd", rpm:"lighttpd~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_ajp13", rpm:"lighttpd-mod_ajp13~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_auth", rpm:"lighttpd-mod_auth~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_file", rpm:"lighttpd-mod_authn_file~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_ldap", rpm:"lighttpd-mod_authn_ldap~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_authn_mysql", rpm:"lighttpd-mod_authn_mysql~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_cml", rpm:"lighttpd-mod_cml~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_deflate", rpm:"lighttpd-mod_deflate~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_geoip", rpm:"lighttpd-mod_geoip~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_magnet", rpm:"lighttpd-mod_magnet~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_mysql_vhost", rpm:"lighttpd-mod_mysql_vhost~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_trigger_b4_dl", rpm:"lighttpd-mod_trigger_b4_dl~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_uploadprogress", rpm:"lighttpd-mod_uploadprogress~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lighttpd-mod_webdav", rpm:"lighttpd-mod_webdav~1.4.59~1.2.mga8", rls:"MAGEIA8"))) {
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
