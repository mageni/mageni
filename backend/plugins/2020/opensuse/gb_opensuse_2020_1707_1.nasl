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
  script_oid("1.3.6.1.4.1.25623.1.0.853514");
  script_version("2020-10-29T06:27:27+0000");
  script_cve_id("CVE-2020-12108", "CVE-2020-12137", "CVE-2020-15011");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-10-29 11:17:52 +0000 (Thu, 29 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-23 03:01:25 +0000 (Fri, 23 Oct 2020)");
  script_name("openSUSE: Security Advisory for Recommended (openSUSE-SU-2020:1707-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1707-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00047.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Recommended'
  package(s) announced via the openSUSE-SU-2020:1707-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mailman to version 2.1.34 fixes the following issues:

  - The fix for lp#1859104 can result in ValueError being thrown
  on attempts to subscribe to a list. This is fixed and extended to apply
  REFUSE_SECOND_PENDING to unsubscription as well. (lp#1878458)

  - DMARC mitigation no longer misses if the domain name returned by DNS
  contains upper case. (lp#1881035)

  - A new WARN_MEMBER_OF_SUBSCRIBE setting can be set to No to prevent
  mailbombing of a member of a list with private rosters by repeated
  subscribe attempts. (lp#1883017)

  - Very long filenames for scrubbed attachments are now truncated.
  (lp#1884456)

  - A content injection vulnerability via the private login page has been
  fixed. CVE-2020-15011  (lp#1877379, bsc#1173369)

  - A content injection vulnerability via the options login page has been
  discovered and reported by Vishal Singh. CVE-2020-12108 (lp#1873722,
  bsc#1171363)

  - Bounce recognition for a non-compliant Yahoo format is added.

  - Archiving workaround for non-ascii in string.lowercase in some Python
  packages is added.

  - Thanks to Jim Popovitch, there is now a dmarc_moderation_addresses list
  setting that can be used to apply dmarc_moderation_action to mail From:
  addresses listed
  or matching listed regexps. This can be used to modify mail to
  addresses that don't accept external mail From: themselves.

  - There is a new MAX_LISTNAME_LENGTH setting. The fix for lp#1780874
  obtains a list of the names of all the all the lists in the
  installation in order to determine the maximum length of a legitimate
  list name. It does this on every web access and on sites with a very
  large number of lists, this can have performance implications. See the
  description in Defaults.py for more information.

  - Thanks to Ralf Jung there is now the ability to add text based captchas
  (aka textchas) to the listinfo subscribe form. See the documentation
  for the new CAPTCHA setting in Defaults.py for how to enable this. Also
  note that if you have custom listinfo.html templates, you will have to
  add a <mm-captcha-ui> tag to those templates to make this work. This
  feature can be used in combination with or instead of the Google
  reCAPTCHA feature added in 2.1.26.

  - Thanks to Ralf Hildebrandt the web admin Membership Management section
  now has a feature to sync the list's membership with a list of email
  addresses as with the bin/sync_members command.

  - There is a new drop_cc list attribute set from DEFAULT_DROP_CC. This
  controls the dropping of addresses from the Cc: header in delivered
  messages by the duplicate avoidance  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'Recommended' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"mailman", rpm:"mailman~2.1.34~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mailman-debuginfo", rpm:"mailman-debuginfo~2.1.34~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mailman-debugsource", rpm:"mailman-debugsource~2.1.34~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
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