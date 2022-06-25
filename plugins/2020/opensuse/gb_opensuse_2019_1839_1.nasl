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
  script_oid("1.3.6.1.4.1.25623.1.0.852959");
  script_version("2020-01-16T07:19:44+0000");
  script_cve_id("CVE-2019-11358", "CVE-2019-12308", "CVE-2019-12781", "CVE-2019-14232",
                "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-16 07:19:44 +0000 (Thu, 16 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 09:47:56 +0000 (Thu, 09 Jan 2020)");
  script_name("openSUSE Update for python-Django openSUSE-SU-2019:1839-1 (python-Django)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-08/msg00006.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-Django'
  package(s) announced via the openSUSE-SU-2019:1839_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-Django fixes the following issues:

  Security issues fixed:

  - CVE-2019-11358: Fixed prototype pollution.

  - CVE-2019-12308: Fixed XSS in AdminURLFieldWidget (bsc#1136468)

  - CVE-2019-12781: Fixed incorrect HTTP detection with reverse-proxy
  connecting via HTTPS (bsc#1139945).

  - CVE-2019-14232: Fixed denial-of-service possibility in
  ``django.utils.text.Truncator`` (bsc#1142880).

  - CVE-2019-14233: Fixed denial-of-service possibility in ``strip_tags()``
  (bsc#1142882).

  - CVE-2019-14234: Fixed SQL injection possibility in key and index lookups
  for ``JSONField``/``HStoreField`` (bsc#1142883).

  - CVE-2019-14235: Fixed potential memory exhaustion in
  ``django.utils.encoding.uri_to_iri()`` (bsc#1142885).

  Non-security issues fixed:

  - Fixed a migration crash on PostgreSQL when adding a check constraint
  with a contains lookup on DateRangeField or DateTimeRangeField, if the
  right hand side of an expression is the same type.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-1839=1");

  script_tag(name:"affected", value:"'python-Django' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-Django", rpm:"python3-Django~2.2.4~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
