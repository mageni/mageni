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
  script_oid("1.3.6.1.4.1.25623.1.0.854168");
  script_version("2021-09-22T08:01:20+0000");
  script_cve_id("CVE-2021-32785", "CVE-2021-32786", "CVE-2021-32791", "CVE-2021-32792");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-04 17:27:00 +0000 (Wed, 04 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-09-17 01:03:53 +0000 (Fri, 17 Sep 2021)");
  script_name("openSUSE: Security Advisory for apache2-mod_auth_openidc (openSUSE-SU-2021:1277-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1277-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4FGDDGUNYC724M4QGEPJORKASFRVKJ5V");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2-mod_auth_openidc'
  package(s) announced via the openSUSE-SU-2021:1277-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_auth_openidc fixes the following issues:

  - CVE-2021-32785: format string bug via hiredis (bsc#1188638)

  - CVE-2021-32786: open redirect in logout functionality (bsc#1188639)

  - CVE-2021-32791: Hardcoded static IV and AAD with a reused key in AES GCM
       encryption (bsc#1188849)

  - CVE-2021-32792: XSS when using OIDCPreservePost On (bsc#1188848)

     This update was imported from the SUSE:SLE-15-SP1:Update update project.");

  script_tag(name:"affected", value:"'apache2-mod_auth_openidc' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc", rpm:"apache2-mod_auth_openidc~2.3.8~lp152.5.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc-debuginfo", rpm:"apache2-mod_auth_openidc-debuginfo~2.3.8~lp152.5.6.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_auth_openidc-debugsource", rpm:"apache2-mod_auth_openidc-debugsource~2.3.8~lp152.5.6.1", rls:"openSUSELeap15.2"))) {
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