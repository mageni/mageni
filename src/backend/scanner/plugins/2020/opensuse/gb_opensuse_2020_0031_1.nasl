# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852985");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2017-7418", "CVE-2019-12815", "CVE-2019-18217", "CVE-2019-19269", "CVE-2019-19270");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-14 04:01:24 +0000 (Tue, 14 Jan 2020)");
  script_name("openSUSE Update for proftpd openSUSE-SU-2020:0031-1 (proftpd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-01/msg00009.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd'
  package(s) announced via the openSUSE-SU-2020:0031_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for proftpd fixes the following issues:

  * GeoIP has been discontinued by Maxmind (boo#1156210) This update removes
  module build for geoip.

  - CVE-2019-19269: Fixed a NULL pointer dereference may occur when
  validating the certificate of a client connecting to the server
  (boo#1157803)

  - CVE-2019-19270: Fixed a Failure to check for the appropriate field of a
  CRL entry prevents some valid CRLs from being taken into account
  (boo#1157798)

  - CVE-2019-18217: Fixed remote unauthenticated denial-of-service due to
  incorrect handling of overly long commands (boo#1154600 gh#846)

  Update to 1.3.6b

  * Fixed pre-authentication remote denial-of-service issue (Issue #846).

  * Backported fix for building mod_sql_mysql using MySQL 8 (Issue #824).

  Update to 1.3.6a:

  * Fixed symlink navigation (Bug#4332).

  * Fixed building of mod_sftp using OpenSSL 1.1.x releases (Issue#674).

  * Fixed SITE COPY honoring of <Limit> restrictions (Bug#4372).

  * Fixed segfault on login when using mod_sftp + mod_sftp_pam (Issue#656).

  * Fixed restarts when using mod_facl as a static module

  * Add missing Requires(pre): group(ftp) for Leap 15 and Tumbleweed
  (boo#1155834)

  * Add missing Requires(pre): user(ftp) for Leap 15 and Tumbleweed
  (boo#1155834)

  * Use pam_keyinit.so (boo#1144056)

  - Reduce hard dependency on systemd to only that which is necessary for
  building and installation.

  update to 1.3.6:

  * Support for using Redis for caching, logging, see the
  doc/howto/Redis.html documentation.

  * Fixed mod_sql_postgres SSL support (Issue #415).

  * Support building against LibreSSL instead of OpenSSL (Issue #361).

  * Better support on AIX for login restraictions (Bug #4285).

  * TimeoutLogin (and other timeouts) were not working properly for SFTP
  connections (Bug#4299).

  * Handling of the SIGILL and SIGINT signals, by the daemon process, now
  causes the child processes to be terminated as well (Issue #461).

  * RPM .spec file naming changed to conform to Fedora guidelines.

  * Fix for 'AllowChrootSymlinks off' checking each component for symlinks
  (CVE-2017-7418).

  New Modules:

  * mod_redis, mod_tls_redis, mod_wrap2_redis With Redis now supported as a
  caching mechanism, similar to Memcache, there are now Redis-using
  modules: mod_redis (for configuring the Redis connection information),
  mod_tls_redis (for caching SSL sessions and OCSP information using
  Redis), and mod_wrap2_redis ..

Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'proftpd' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"proftpd", rpm:"proftpd~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-debuginfo", rpm:"proftpd-debuginfo~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-debugsource", rpm:"proftpd-debugsource~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-devel", rpm:"proftpd-devel~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-doc", rpm:"proftpd-doc~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-ldap", rpm:"proftpd-ldap~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-ldap-debuginfo", rpm:"proftpd-ldap-debuginfo~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mysql", rpm:"proftpd-mysql~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-mysql-debuginfo", rpm:"proftpd-mysql-debuginfo~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-pgsql", rpm:"proftpd-pgsql~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-pgsql-debuginfo", rpm:"proftpd-pgsql-debuginfo~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-radius", rpm:"proftpd-radius~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-radius-debuginfo", rpm:"proftpd-radius-debuginfo~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-sqlite", rpm:"proftpd-sqlite~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-sqlite-debuginfo", rpm:"proftpd-sqlite-debuginfo~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"proftpd-lang", rpm:"proftpd-lang~1.3.6b~lp151.3.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
