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
  script_oid("1.3.6.1.4.1.25623.1.0.884265");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-4254");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-31 02:01:21 +0000 (Tue, 31 Jan 2023)");
  script_name("CentOS: Security Advisory for libipa_hbac (CESA-2023:0403)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:0403");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-January/086361.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libipa_hbac'
  package(s) announced via the CESA-2023:0403 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The System Security Services Daemon (SSSD) service provides a set of
daemons to manage access to remote directories and authentication
mechanisms. It also provides the Name Service Switch (NSS) and the
Pluggable Authentication Modules (PAM) interfaces toward the system, and a
pluggable back-end system to connect to multiple different account sources.

Security Fix(es):

  * sssd: libsss_certmap fails to sanitise certificate data used in LDAP
filters (CVE-2022-4254)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * smartcards: special characters must be escaped when building search
filter (BZ#2149703)");

  script_tag(name:"affected", value:"'libipa_hbac' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac", rpm:"libipa_hbac~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libipa_hbac-devel", rpm:"libipa_hbac-devel~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_autofs", rpm:"libsss_autofs~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap", rpm:"libsss_certmap~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_certmap-devel", rpm:"libsss_certmap-devel~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap", rpm:"libsss_idmap~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_idmap-devel", rpm:"libsss_idmap-devel~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap", rpm:"libsss_nss_idmap~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_nss_idmap-devel", rpm:"libsss_nss_idmap-devel~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp", rpm:"libsss_simpleifp~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_simpleifp-devel", rpm:"libsss_simpleifp-devel~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsss_sudo", rpm:"libsss_sudo~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libipa_hbac", rpm:"python-libipa_hbac~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libsss_nss_idmap", rpm:"python-libsss_nss_idmap~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sss", rpm:"python-sss~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sssdconfig", rpm:"python-sssdconfig~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-sss-murmur", rpm:"python-sss-murmur~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd", rpm:"sssd~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ad", rpm:"sssd-ad~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-client", rpm:"sssd-client~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common", rpm:"sssd-common~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-common-pac", rpm:"sssd-common-pac~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-dbus", rpm:"sssd-dbus~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ipa", rpm:"sssd-ipa~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-kcm", rpm:"sssd-kcm~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5", rpm:"sssd-krb5~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-krb5-common", rpm:"sssd-krb5-common~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-ldap", rpm:"sssd-ldap~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-libwbclient", rpm:"sssd-libwbclient~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-libwbclient-devel", rpm:"sssd-libwbclient-devel~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-polkit-rules", rpm:"sssd-polkit-rules~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-proxy", rpm:"sssd-proxy~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-tools", rpm:"sssd-tools~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sssd-winbind-idmap", rpm:"sssd-winbind-idmap~1.16.5~10.el7_9.15", rls:"CentOS7"))) {
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