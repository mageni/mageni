###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1595_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for icedtea-web openSUSE-SU-2015:1595-1 (icedtea-web)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850687");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-09-22 13:09:21 +0200 (Tue, 22 Sep 2015)");
  script_cve_id("CVE-2012-4540", "CVE-2015-5234", "CVE-2015-5235");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for icedtea-web openSUSE-SU-2015:1595-1 (icedtea-web)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The icedtea-web java plugin was updated to 1.6.1.

  Changes included:

  * Enabled Entry-Point attribute check

  * permissions sandbox and signed app and unsigned app with permissions
  all-permissions now run in sandbox instead of not at all.

  * fixed DownloadService

  * comments in deployment.properties now should persists load/save

  * fixed bug in caching of files with query

  * fixed issues with recreating of existing shortcut

  * trustAll/trustNone now processed correctly

  * headless no longer shows dialogues

  * RH1231441 Unable to read the text of the buttons of the security dialogue

  * Fixed RH1233697 icedtea-web: applet origin spoofing (CVE-2015-5235,
  bsc#944208)

  * Fixed RH1233667 icedtea-web: unexpected permanent authorization of
  unsigned applets (CVE-2015-5234, bsc#944209)

  * MissingALACAdialog made available also for unsigned applications (but
  ignoring actual manifest value) and fixed

  * NetX

  - fixed issues with -html shortcuts

  - fixed issue with -html receiving garbage in width and height

  * PolicyEditor

  - file flag made to work when used standalone

  - file flag and main argument cannot be used in combination

  * Fix generation of man-pages with some versions of 'tail'

  Also included is the update to 1.6

  * Massively improved offline abilities. Added Xoffline switch to force
  work without inet connection.

  * Improved to be able to run with any JDK

  * JDK 6 and older no longer supported

  * JDK 8 support added (URLPermission granted if applicable)

  * JDK 9 supported

  * Added support for Entry-Point manifest attribute

  * Added KEY_ENABLE_MANIFEST_ATTRIBUTES_CHECK deployment property to
  control scan of Manifest file

  * starting arguments now accept also -- abbreviations

  * Added new documentation

  * Added support for menu shortcuts - both javaws applications/applets and
  html applets are supported

  * added support for -html switch for javaws. Now you can run most
  of the applets without browser at all

  * Control Panel

  - PR1856: ControlPanel UI improvement for lower resolutions (800*600)

  * NetX

  - PR1858: Java Console accepts multi-byte encodings

  - PR1859: Java Console UI improvement for lower resolutions (800*600)

  - RH1091563: [abrt] icedtea-web-1.5-2.fc20: Uncaught exception
  java.lang.ClassCastException in method
  sun.applet.PluginAppletViewer$8.run()

  - Dropped support for long unmaintained -basedir argument

  - Returned support for -jnlp argument

  - RH1095311, PR574 -  References class sun.misc.Ref removed in OpenJDK 9

  - fixed, and so buildable on JDK9

  * Plugin

  - PR1743 - Intermittent deadlock in P ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"icedtea-web on openSUSE 13.2, openSUSE 13.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE13\.2|openSUSE13\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-plugin", rpm:"java-1_7_0-openjdk-plugin~1.6.1~6.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-plugin-debuginfo", rpm:"java-1_7_0-openjdk-plugin-debuginfo~1.6.1~6.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_7_0-openjdk-plugin-debugsource", rpm:"java-1_7_0-openjdk-plugin-debugsource~1.6.1~6.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-plugin", rpm:"java-1_8_0-openjdk-plugin~1.6.1~6.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-plugin-debuginfo", rpm:"java-1_8_0-openjdk-plugin-debuginfo~1.6.1~6.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"java-1_8_0-openjdk-plugin-debugsource", rpm:"java-1_8_0-openjdk-plugin-debugsource~1.6.1~6.2", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.6.1~6.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.5.3~0.7.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-debuginfo", rpm:"icedtea-web-debuginfo~1.5.3~0.7.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-debugsource", rpm:"icedtea-web-debugsource~1.5.3~0.7.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.5.3~0.7.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}