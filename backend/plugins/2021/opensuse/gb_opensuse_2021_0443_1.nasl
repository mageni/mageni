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
  script_oid("1.3.6.1.4.1.25623.1.0.853581");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2021-20272", "CVE-2021-20273", "CVE-2021-20274", "CVE-2021-20275", "CVE-2021-20276");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:55:18 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for privoxy (openSUSE-SU-2021:0443-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0443-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TFUTCP522RHVYR5DDZPU4P3YHFZXBVYJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'privoxy'
  package(s) announced via the openSUSE-SU-2021:0443-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for privoxy fixes the following issues:

     Update to version 3.0.32:

  - Security/Reliability (boo#1183129)

  - ssplit(): Remove an assertion that could be triggered with a crafted
           CGI request. Commit 2256d7b4d67. OVE-20210203-0001. CVE-2021-20272
           Reported by: Joshua Rogers (Opera)

  - cgi_send_banner(): Overrule invalid image types. Prevents a crash
           with a crafted CGI request if Privoxy is toggled off. Commit
           e711c505c48. OVE-20210206-0001. CVE-2021-20273 Reported by: Joshua
           Rogers (Opera)

  - socks5_connect(): Don&#x27 t try to send credentials when none are
           configured. Fixes a crash due to a NULL-pointer dereference when the
           socks server misbehaves. Commit 85817cc55b9. OVE-20210207-0001.
           CVE-2021-20274 Reported by: Joshua Rogers (Opera)

  - chunked_body_is_complete(): Prevent an invalid read of size two.
           Commit a912ba7bc9c. OVE-20210205-0001. CVE-2021-20275 Reported by:
           Joshua Rogers (Opera)

  - Obsolete pcre: Prevent invalid memory accesses with an invalid
           pattern passed to pcre_compile(). Note that the obsolete pcre code
           is scheduled to be removed before the 3.0.33 release. There has been
           a warning since 2008 already. Commit 28512e5b624. OVE-20210222-0001.
           CVE-2021-20276 Reported by: Joshua Rogers (Opera)

  - Bug fixes:

  - Properly parse the client-tag-lifetime directive. Previously it was
           not accepted as an obsolete hash value was being used. Reported by:
           Joshua Rogers (Opera)

  - decompress_iob(): Prevent reading of uninitialized data. Reported
           by: Joshua Rogers (Opera).

  - decompress_iob(): Don&#x27 t advance cur past eod when looking for the
           end of the file name and comment.

  - decompress_iob(): Cast value to unsigned char before shifting.
           Prevents a left-shift of a negative value which is undefined
           behaviour. Reported by: Joshua Rogers (Opera)

  - buf_copy(): Fail if there&#x27 s no data to write or nothing to do.
           Prevents undefined behaviour 'applying zero offset to null pointer'.
           Reported by: Joshua Rogers (Opera)

  - log_error(): Treat LOG_LEVEL_FATAL as fatal even when --stfu is
           being used while fuzzing. Reported by: Jos ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'privoxy' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"privoxy", rpm:"privoxy~3.0.32~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debuginfo", rpm:"privoxy-debuginfo~3.0.32~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-debugsource", rpm:"privoxy-debugsource~3.0.32~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"privoxy-doc", rpm:"privoxy-doc~3.0.32~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
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
