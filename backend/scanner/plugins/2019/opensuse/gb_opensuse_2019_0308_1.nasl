# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852338");
  script_version("2019-04-09T07:15:29+0000");
  script_cve_id("CVE-2018-4437", "CVE-2018-4438", "CVE-2018-4441", "CVE-2018-4442",
                "CVE-2018-4443", "CVE-2018-4464", "CVE-2019-6212", "CVE-2019-6215",
                "CVE-2019-6216", "CVE-2019-6217", "CVE-2019-6226", "CVE-2019-6227",
                "CVE-2019-6229", "CVE-2019-6233", "CVE-2019-6234");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-04-09 07:15:29 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-09 04:08:40 +0100 (Sat, 09 Mar 2019)");
  script_name("SuSE Update for webkit2gtk3 openSUSE-SU-2019:0308-1 (webkit2gtk3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-03/msg00014.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2019:0308_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 to version 2.22.6 fixes the following issues
  (boo#1124937 boo#1119558):

  Security vulnerabilities fixed:

  - CVE-2018-4437: Processing maliciously crafted web content may lead to
  arbitrary code execution. Multiple memory corruption issues were
  addressed with improved memory handling. (boo#1119553)

  - CVE-2018-4438: Processing maliciously crafted web content may lead to
  arbitrary code execution. A logic issue existed resulting in memory
  corruption. This was addressed with improved state management.
  (boo#1119554)

  - CVE-2018-4441: Processing maliciously crafted web content may lead to
  arbitrary code execution. A memory corruption issue was addressed with
  improved memory handling. (boo#1119555)

  - CVE-2018-4442: Processing maliciously crafted web content may lead to
  arbitrary code execution. A memory corruption issue was addressed with
  improved memory handling. (boo#1119556)

  - CVE-2018-4443: Processing maliciously crafted web content may lead to
  arbitrary code execution. A memory corruption issue was addressed with
  improved memory handling. (boo#1119557)

  - CVE-2018-4464: Processing maliciously crafted web content may lead to
  arbitrary code execution. Multiple memory corruption issues were
  addressed with improved memory handling. (boo#1119558)

  - CVE-2019-6212: Processing maliciously crafted web content may lead to
  arbitrary code execution. Multiple memory corruption issues were
  addressed with improved memory handling.

  - CVE-2019-6215: Processing maliciously crafted web content may lead to
  arbitrary code execution. A type confusion issue was addressed with
  improved memory handling.

  - CVE-2019-6216: Processing maliciously crafted web content may lead to
  arbitrary code execution. Multiple memory corruption issues were
  addressed with improved memory handling.

  - CVE-2019-6217: Processing maliciously crafted web content may lead to
  arbitrary code execution. Multiple memory corruption issues were
  addressed with improved memory handling.

  - CVE-2019-6226: Processing maliciously crafted web content may lead to
  arbitrary code execution. Multiple memory corruption issues were
  addressed with improved memory handling.

  - CVE-2019-6227: Processing maliciously crafted web content may lead to
  arbitrary code execution. A memory corruption issue was addressed with
  improved memory handling.

  - CVE-2019-6229: Processing maliciously crafted web content may lead to
  universal cross site scripting. A logic issue was addressed with
  improved validation.

  - CVE-2019-6233: Processing maliciously crafted web ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"webkit2gtk3 on openSUSE Leap 15.0.");

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

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-minibrowser", rpm:"webkit2gtk3-minibrowser~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-minibrowser-debuginfo", rpm:"webkit2gtk3-minibrowser-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-plugin-process-gtk2", rpm:"webkit2gtk3-plugin-process-gtk2~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-plugin-process-gtk2-debuginfo", rpm:"webkit2gtk3-plugin-process-gtk2-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-32bit-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit-debuginfo", rpm:"libwebkit2gtk-4_0-37-32bit-debuginfo~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.22.6~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
