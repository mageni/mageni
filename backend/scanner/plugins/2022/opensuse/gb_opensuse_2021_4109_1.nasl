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
  script_oid("1.3.6.1.4.1.25623.1.0.854379");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-44228");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 06:34:08 +0000 (Tue, 01 Feb 2022)");
  script_name("openSUSE: Security Advisory for logback (openSUSE-SU-2021:4109-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:4109-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/GICANZVVUJZMKRG5INZ4A2FGAEWOEJQD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'logback'
  package(s) announced via the openSUSE-SU-2021:4109-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for logback fixes the following issues:
  Upgrade to version 1.2.8
  + In response to log4Shell/CVE-2021-44228, all JNDI lookup code in logback
       has been disabled until further notice. This impacts ContextJNDISelector
       and insertFromJNDI element in configuration files.
     + Also in response to log4Shell/CVE-2021-44228, all database (JDBC)
       related code in the project has been removed with no replacement.
     + Note that the vulnerability mentioned in LOGBACK-1591 requires write
       access to logback's configuration file as a prerequisite. The
       log4Shell/CVE-2021-44228 and LOGBACK-1591 are of different severity
       levels. A successful RCE requires all of the following conditions to be
       met:

  - write access to logback.xml

  - use of versions lower then 1.2.8

  - reloading of poisoned configuration data, which implies application
         restart or scan='true' set prior to attack");

  script_tag(name:"affected", value:"'logback' package(s) on openSUSE Leap 15.3.");

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

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"logback", rpm:"logback~1.2.8~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"logback-access", rpm:"logback-access~1.2.8~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"logback-examples", rpm:"logback-examples~1.2.8~3.3.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"logback-javadoc", rpm:"logback-javadoc~1.2.8~3.3.1", rls:"openSUSELeap15.3"))) {
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