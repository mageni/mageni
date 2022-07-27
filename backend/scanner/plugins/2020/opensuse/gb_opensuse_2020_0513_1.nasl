# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.853113");
  script_version("2020-04-21T09:23:28+0000");
  script_cve_id("CVE-2019-10206", "CVE-2019-10217", "CVE-2019-14846", "CVE-2019-14856", "CVE-2019-14858", "CVE-2019-14864", "CVE-2019-14904", "CVE-2019-14905");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-04-21 10:11:05 +0000 (Tue, 21 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-13 03:00:35 +0000 (Mon, 13 Apr 2020)");
  script_name("openSUSE: Security Advisory for ansible (openSUSE-SU-2020:0513-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00021.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ansible'
  package(s) announced via the openSUSE-SU-2020:0513-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ansible to version 2.9.6 fixes the following issues:

  Security issues fixed:

  - CVE-2019-14904: Fixed a vulnerability in solaris_zone module via crafted
  solaris zone (boo#1157968).

  - CVE-2019-14905: Fixed an issue where malicious code could craft filename
  in nxos_file_copy module (boo#1157969).

  - CVE-2019-14864: Fixed Splunk and Sumologic callback plugins leak
  sensitive data in logs (boo#1154830).

  - CVE-2019-14846: Fixed secrets disclosure on logs due to display is
  hardcoded to DEBUG level (boo#1153452)

  - CVE-2019-14856: Fixed insufficient fix for CVE-2019-10206 (boo#1154232)

  - CVE-2019-14858: Fixed data in the sub parameter fields that will not be
  masked and will be displayed when run with increased verbosity
  (boo#1154231)

  - CVE-2019-10206: ansible-playbook -k and ansible cli tools prompt
  passwords by expanding them from templates as they could contain special
  characters. Passwords should be wrapped to prevent templates trigger and
  exposing them. (boo#1142690)

  - CVE-2019-10217: Fields managing sensitive data should be set as such by
  no_log feature. Some of these fields in GCP modules are not set
  properly. service_account_contents() which is common class for all gcp
  modules is not setting no_log to True. Any sensitive data managed by
  that function would be leak as an output when running ansible playbooks.
  (boo#1144453)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-513=1");

  script_tag(name:"affected", value:"'ansible' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"ansible", rpm:"ansible~2.9.6~lp151.2.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-doc", rpm:"ansible-doc~2.9.6~lp151.2.7.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ansible-test", rpm:"ansible-test~2.9.6~lp151.2.7.1", rls:"openSUSELeap15.1"))) {
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