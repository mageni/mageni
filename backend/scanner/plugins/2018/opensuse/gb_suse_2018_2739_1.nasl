###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2739_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libzypp, openSUSE-SU-2018:2739-1 (libzypp,)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852022");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2017-9269", "CVE-2018-7685");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:35:05 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for libzypp, openSUSE-SU-2018:2739-1 (libzypp, )");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-09/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp, '
  package(s) announced via the openSUSE-SU-2018:2739_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp, zypper, libsolv provides the following fixes:

  Security fixes in libzypp:

  - CVE-2018-7685: PackageProvider: Validate RPMs before caching
  (bsc#1091624, bsc#1088705)

  - CVE-2017-9269: Be sure bad packages do not stay in the cache
  (bsc#1045735)

  Changes in libzypp:

  - Update to version 17.6.4

  - Automatically fetch repository signing key from gpgkey url (bsc#1088037)

  - lsof: use '-K i' if lsof supports it (bsc#1099847, bsc#1036304)

  - Check for not imported keys after multi key import from rpmdb
  (bsc#1096217)

  - Flags: make it std=c++14 ready

  - Ignore /var, /tmp and /proc in zypper ps. (bsc#1096617)

  - Show GPGME version in log

  - Adapt to changes in libgpgme11-11.1.0 breaking the signature
  verification (bsc#1100427)

  - RepoInfo::provideKey: add report telling where we look for missing keys.

  - Support listing gpgkey URLs in repo files (bsc#1088037)

  - Add new report to request user approval for importing a package key

  - Handle http error 502 Bad Gateway in curl backend (bsc#1070851)

  - Add filesize check for downloads with known size (bsc#408814)

  - Removed superfluous space in translation (bsc#1102019)

  - Prevent the system from sleeping during a commit

  - RepoManager: Explicitly request repo2solv to generate application pseudo
  packages.

  - libzypp-devel should not require cmake (bsc#1101349)

  - Avoid zombies from ExternalProgram

  - Update ApiConfig

  - HardLocksFile: Prevent against empty commit without Target having been
  been loaded (bsc#1096803)

  - lsof: use '-K i' if lsof supports it (bsc#1099847)

  - Add filesize check for downloads with known size (bsc#408814)

  - Fix detection of metalink downloads and prevent aborting if a metalink
  file is larger than the expected data file.

  - Require libsolv-devel  = 0.6.35 during build (fixing bsc#1100095)

  - Make use of %license macro (bsc#1082318)

  Security fix in zypper:

  - CVE-2017-9269: Improve signature check callback messages (bsc#1045735)

  Changes in zypper:

  - Always set error status if any nr of unknown repositories are passed to
  lr and ref (bsc#1093103)

  - Notify user about unsupported rpm V3 keys in an old rpm database
  (bsc#1096217)

  - Detect read only filesystem on system modifying operations (fixes #199)

  - Use %license (bsc#1082318)

  - Handle repo aliases containing multiple ':' in the PackageArgs parser
  (bsc #1041178)

  - Fix broken display of detailed query results.

  - Fix broken search for items with a dash. (bsc#907538, bsc#1043166,
  bsc#1070770)

  - Disable repository operations when searching installed packages.
  (bsc#1084525)
 ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"libzypp, on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libsolv-debuginfo", rpm:"libsolv-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-debugsource", rpm:"libsolv-debugsource~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-demo", rpm:"libsolv-demo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-demo-debuginfo", rpm:"libsolv-demo-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-devel", rpm:"libsolv-devel~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-devel-debuginfo", rpm:"libsolv-devel-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-tools", rpm:"libsolv-tools~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsolv-tools-debuginfo", rpm:"libsolv-tools-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~17.6.4~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-debuginfo", rpm:"libzypp-debuginfo~17.6.4~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-debugsource", rpm:"libzypp-debugsource~17.6.4~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~17.6.4~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzypp-devel-doc", rpm:"libzypp-devel-doc~17.6.4~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-solv", rpm:"perl-solv~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"perl-solv-debuginfo", rpm:"perl-solv-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-solv", rpm:"python-solv~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-solv-debuginfo", rpm:"python-solv-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-solv", rpm:"python3-solv~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-solv-debuginfo", rpm:"python3-solv-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-solv", rpm:"ruby-solv~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-solv-debuginfo", rpm:"ruby-solv-debuginfo~0.6.35~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.14.10~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zypper-debuginfo", rpm:"zypper-debuginfo~1.14.10~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zypper-debugsource", rpm:"zypper-debugsource~1.14.10~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zypper-aptitude", rpm:"zypper-aptitude~1.14.10~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.14.10~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
