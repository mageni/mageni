# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853277");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2020-8903", "CVE-2020-8907", "CVE-2020-8933");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-19 03:00:54 +0000 (Sun, 19 Jul 2020)");
  script_name("openSUSE: Security Advisory for google-compute-engine (openSUSE-SU-2020:0996-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0996-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00037.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'google-compute-engine'
  package(s) announced via the openSUSE-SU-2020:0996-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for google-compute-engine fixes the following issues:

  - Don't enable and start google-network-daemon.service when it's already
  installed (bsc#1169978)

  + Do not add the created user to the adm (CVE-2020-8903), docker
  (CVE-2020-8907), or lxd (CVE-2020-8933) groups if they exist
  (bsc#1173258) This update was imported from the SUSE:SLE-15:Update
  update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-996=1");

  script_tag(name:"affected", value:"'google-compute-engine' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"google-compute-engine-debugsource-20190801", rpm:"google-compute-engine-debugsource-20190801~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-compute-engine-oslogin-20190801", rpm:"google-compute-engine-oslogin-20190801~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-compute-engine-oslogin-debuginfo-20190801", rpm:"google-compute-engine-oslogin-debuginfo-20190801~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-compute-engine-oslogin-32bit-20190801", rpm:"google-compute-engine-oslogin-32bit-20190801~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-compute-engine-oslogin-32bit-debuginfo-20190801", rpm:"google-compute-engine-oslogin-32bit-debuginfo-20190801~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"google-compute-engine-init-20190801", rpm:"google-compute-engine-init-20190801~lp151.2.25.1", rls:"openSUSELeap15.1"))) {
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
