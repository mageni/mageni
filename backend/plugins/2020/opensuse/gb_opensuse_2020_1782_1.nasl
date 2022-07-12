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
  script_oid("1.3.6.1.4.1.25623.1.0.853551");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-25654");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-03 04:01:54 +0000 (Tue, 03 Nov 2020)");
  script_name("openSUSE: Security Advisory for pacemaker (openSUSE-SU-2020:1782-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1782-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00076.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pacemaker'
  package(s) announced via the openSUSE-SU-2020:1782-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pacemaker fixes the following issues:

  Update to 2.0.4:

  - based: use crm_exit to free qb-logging

  - cibsecret: don't use pssh -q option unless supported

  - crm_error: use g_free for a proper match

  - crm_mon: NULL output-pointer when buffer is freed

  - crm_resource: avoid unnecessary issus with dynamic allocation

  - crm_ticket: avoid unnecessary issues with dynamic allocation

  - executor: restrict certain IPC requests to Pacemaker daemons
  (CVE-2020-25654, bsc#1177916)

  - fencer: avoid infinite loop if device is removed during operation

  - fencer: restrict certain IPC requests to privileged users
  (CVE-2020-25654, bsc#1177916)

  - libcrmcommon: free basename after setting prgname

  - libcrmcommon: return ENOMEM directly instead of errno

  - libpe_status: Modify filtering of inactive resources.

  - libreplace: closedir when bailing out dir traversal

  - move bcond_with/without up front for e.g. pcmk_release

  - pacemakerd: ignore shutdown requests from unprivileged users
  (CVE-2020-25654, bsc#1177916)

  - resources: attribute name parameter doesn't have to be unique

  - rpm: add spec option for enabling CIB secrets

  - rpm: put user-configurable items at top of spec

  - rpm: use the user/group ID 90 for haclient/hacluster to be consistent
  with cluster-glue (bsc#1167171)

  - scheduler: Add the node name back to bundle instances.

  - silence some false positives static analysis stumbled over

  - tools: check resource separately from managing parameter in cibsecret

  - tools: free IPC memory after closing connection

  - tools: improve cibsecret help

  - tools: verify newly created CIB connection is not NULL

  This update was imported from the SUSE:SLE-15-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1782=1");

  script_tag(name:"affected", value:"'pacemaker' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpacemaker-devel", rpm:"libpacemaker-devel~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpacemaker3", rpm:"libpacemaker3~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpacemaker3-debuginfo", rpm:"libpacemaker3-debuginfo~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker", rpm:"pacemaker~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cli", rpm:"pacemaker-cli~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cli-debuginfo", rpm:"pacemaker-cli-debuginfo~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-debuginfo", rpm:"pacemaker-debuginfo~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-debugsource", rpm:"pacemaker-debugsource~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-remote", rpm:"pacemaker-remote~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-remote-debuginfo", rpm:"pacemaker-remote-debuginfo~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pacemaker-cts", rpm:"pacemaker-cts~2.0.4+20200616.2deceaa3a~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
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