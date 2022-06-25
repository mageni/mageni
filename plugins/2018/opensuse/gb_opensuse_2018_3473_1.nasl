###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3473_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for webkit2gtk3 openSUSE-SU-2018:3473-1 (webkit2gtk3)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852089");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2017-13884", "CVE-2017-13885", "CVE-2017-7153", "CVE-2017-7160", "CVE-2017-7161", "CVE-2017-7165", "CVE-2018-11646", "CVE-2018-11712", "CVE-2018-11713", "CVE-2018-12911", "CVE-2018-4088", "CVE-2018-4096", "CVE-2018-4101", "CVE-2018-4113", "CVE-2018-4114", "CVE-2018-4117", "CVE-2018-4118", "CVE-2018-4119", "CVE-2018-4120", "CVE-2018-4121", "CVE-2018-4122", "CVE-2018-4125", "CVE-2018-4127", "CVE-2018-4128", "CVE-2018-4129", "CVE-2018-4133", "CVE-2018-4146", "CVE-2018-4161", "CVE-2018-4162", "CVE-2018-4163", "CVE-2018-4165", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4200", "CVE-2018-4204", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233", "CVE-2018-4246");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:43:57 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for webkit2gtk3 openSUSE-SU-2018:3473-1 (webkit2gtk3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00071.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the openSUSE-SU-2018:3473_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 to version 2.20.3 fixes the issues:

  The following security vulnerabilities were addressed:

  - CVE-2018-12911: Fixed an off-by-one error in xdg_mime_get_simple_globs
  (boo#1101999)

  - CVE-2017-13884: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1075775).

  - CVE-2017-13885: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1075775).

  - CVE-2017-7153: An unspecified issue allowed remote attackers to spoof
  user-interface information (about whether the entire content is derived
  from a valid TLS session) via a crafted web site that sends a 401
  Unauthorized redirect (bsc#1077535).

  - CVE-2017-7160: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1075775).

  - CVE-2017-7161: An unspecified issue allowed remote attackers to execute
  arbitrary code via special characters that trigger command injection
  (bsc#1075775, bsc#1077535).

  - CVE-2017-7165: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1075775).

  - CVE-2018-4088: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1075775).

  - CVE-2018-4096: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1075775).

  - CVE-2018-4200: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site that triggers a
  WebCore::jsElementScrollHeightGetter use-after-free (bsc#1092280).

  - CVE-2018-4204: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1092279).

  - CVE-2018-4101: An unspecified issue allowed remote attackers to execute
  arbitrary code or cause a denial of service (memory corruption and
  application crash) via a crafted web site (bsc#1088182).

  - CVE-2018-4113: An issue in the JavaScriptCore function in the 'WebKi ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"webkit2gtk3 on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-plugin-process-gtk2", rpm:"webkit2gtk3-plugin-process-gtk2~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-plugin-process-gtk2-debuginfo", rpm:"webkit2gtk3-plugin-process-gtk2-debuginfo~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo-32bit", rpm:"libjavascriptcoregtk-4_0-18-debuginfo-32bit~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo-32bit", rpm:"libwebkit2gtk-4_0-37-debuginfo-32bit~2.20.3~11.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
