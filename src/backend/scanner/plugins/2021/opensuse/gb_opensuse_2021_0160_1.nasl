# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853662");
  script_version("2021-04-21T07:29:02+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:59:15 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for stunnel (openSUSE-SU-2021:0160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0160-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q7XK4JAT2VTRMB2I2BVA3DY34276OGEH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'stunnel'
  package(s) announced via the openSUSE-SU-2021:0160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for stunnel fixes the following issues:

     Security issue fixed:

  - The 'redirect' option was fixed to properly handle 'verifyChain =
  yes'
       (bsc#1177580).

     Non-security issues fixed:

  - Fix startup problem of the stunnel daemon (bsc#1178533)

  - update to 5.57:

  * Security bugfixes

  * New features

  - New securityLevel configuration file option.

  - Support for modern PostgreSQL clients

  - TLS 1.3 configuration updated for better compatibility.

  * Bugfixes

  - Fixed a transfer() loop bug.

  - Fixed memory leaks on configuration reloading errors.

  - DH/ECDH initialization restored for client sections.

  - Delay startup with systemd until network is online.

  - A number of testing framework fixes and improvements.

  - update to 5.56:

  - Various text files converted to Markdown format.

  - Support for realpath(3) implementations incompatible with
         POSIX.1-2008, such as 4.4BSD or Solaris.

  - Support for engines without PRNG seeding methods (thx to Petr
         Mikhalitsyn).

  - Retry unsuccessful port binding on configuration file reload.

  - Thread safety fixes in SSL_SESSION object handling.

  - Terminate clients on exit in the FORK threading model.

  - Fixup stunnel.conf handling:

  * Remove old static openSUSE provided stunnel.conf.

  * Use upstream stunnel.conf and tailor it for openSUSE using sed.

  * Don&#x27 t show README.openSUSE when installing.

  - enable /etc/stunnel/conf.d

  - re-enable openssl.cnf

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'stunnel' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"stunnel-doc", rpm:"stunnel-doc~5.57~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stunnel", rpm:"stunnel~5.57~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stunnel-debuginfo", rpm:"stunnel-debuginfo~5.57~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"stunnel-debugsource", rpm:"stunnel-debugsource~5.57~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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