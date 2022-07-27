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
  script_oid("1.3.6.1.4.1.25623.1.0.853265");
  script_version("2020-07-24T07:28:01+0000");
  script_cve_id("CVE-2020-8024");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-24 10:05:16 +0000 (Fri, 24 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-15 03:00:58 +0000 (Wed, 15 Jul 2020)");
  script_name("openSUSE: Security Advisory for hylafax+ (openSUSE-SU-2020:0958-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0958-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-07/msg00022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hylafax+'
  package(s) announced via the openSUSE-SU-2020:0958-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for hylafax+ fixes the following issues:

  Security issue fixed:

  - CVE-2020-8024 boo#1172731

  hylafax+ was updated to version 7.0.2:

  * change FIXEDWIDTH default to better accommodate auto-rotation (13 Dec
  2019)

  * prevent SSL_accept() from blocking (5 Dec 2019)

  * support libtiff v4.1 (5 Dec 2019)

  * fix ignoremodembusy feature broken by ModemGroup limits feature (16 Nov
  2019)

  Version 7.0.1:

  * create a client timeout setting and change the default from 60 to 3600
  seconds (26 Sep 2019)

  * extend timeout for receiving ECM frames (21 Aug 2019)

  * fix timeout in Class 1 frame reception (5 Aug 2019)

  * improve Class 1 protocol handling when MaxRecvPages exceeded (31 Jul
  2019)

  * fix ModemGroup limit default (11 Jul 2019)

  * fix recovery for SSL Fax write failures (6 Jun 2019)

  Version 7.0.0:

  * add LDAP features for compatibility with ActiveDirectory (25 Mar-1 Apr
  2019)

  * fix recovery after SSL Fax 'accept failure' (18 Mar 2019)

  * add TextFormat overstrike option and disable by default (6 Feb 2019)

  * fix the page size of cover sheets returned via notify (8 Jan 2019)

  * fix or silence numerous compiler warnings (19, 22, 28 Dec 2018)

  * fix pagehandling updating after a proxy has been used (7-8 Dec 2018)

  * add faxmail stderr output of RFC2047 decoding results (5 Dec 2018)

  * fix faxmail handling of headers encoded with UTF-8 (4 Dec 2018)

  * fix faxmail handling of base64-encoded text parts (4 Dec 2018)

  * add SSL Fax support (9-26, 29 Nov, 11, 18, 25 Dec 2018, 2, 7, 23 Jan
  2019)


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-958=1");

  script_tag(name:"affected", value:"'hylafax+' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"hylafax+", rpm:"hylafax+~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client", rpm:"hylafax+-client~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client-debuginfo", rpm:"hylafax+-client-debuginfo~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-debuginfo", rpm:"hylafax+-debuginfo~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-debugsource", rpm:"hylafax+-debugsource~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfaxutil7_0_2", rpm:"libfaxutil7_0_2~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfaxutil7_0_2-debuginfo", rpm:"libfaxutil7_0_2-debuginfo~7.0.2~lp151.4.3.1", rls:"openSUSELeap15.1"))) {
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