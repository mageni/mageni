###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0326_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for webkit2gtk3 openSUSE-SU-2018:0326-1 (webkit2gtk3)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851693");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-01 07:49:36 +0100 (Thu, 01 Feb 2018)");
  script_cve_id("CVE-2016-4692", "CVE-2016-4743", "CVE-2016-7586", "CVE-2016-7587",
                "CVE-2016-7589", "CVE-2016-7592", "CVE-2016-7598", "CVE-2016-7599",
                "CVE-2016-7610", "CVE-2016-7623", "CVE-2016-7632", "CVE-2016-7635",
                "CVE-2016-7639", "CVE-2016-7641", "CVE-2016-7645", "CVE-2016-7652",
                "CVE-2016-7654", "CVE-2016-7656", "CVE-2017-13788", "CVE-2017-13798",
                "CVE-2017-13803", "CVE-2017-13856", "CVE-2017-13866", "CVE-2017-13870",
                "CVE-2017-2350", "CVE-2017-2354", "CVE-2017-2355", "CVE-2017-2356",
                "CVE-2017-2362", "CVE-2017-2363", "CVE-2017-2364", "CVE-2017-2365",
                "CVE-2017-2366", "CVE-2017-2369", "CVE-2017-2371", "CVE-2017-2373",
                "CVE-2017-2496", "CVE-2017-2510", "CVE-2017-2539", "CVE-2017-5715",
                "CVE-2017-5753", "CVE-2017-5754", "CVE-2017-7006", "CVE-2017-7011",
                "CVE-2017-7012", "CVE-2017-7018", "CVE-2017-7019", "CVE-2017-7020",
                "CVE-2017-7030", "CVE-2017-7034", "CVE-2017-7037", "CVE-2017-7038",
                "CVE-2017-7039", "CVE-2017-7040", "CVE-2017-7041", "CVE-2017-7042",
                "CVE-2017-7043", "CVE-2017-7046", "CVE-2017-7048", "CVE-2017-7049",
                "CVE-2017-7052", "CVE-2017-7055", "CVE-2017-7056", "CVE-2017-7059",
                "CVE-2017-7061", "CVE-2017-7064", "CVE-2017-7081", "CVE-2017-7087",
                "CVE-2017-7089", "CVE-2017-7090", "CVE-2017-7091", "CVE-2017-7092",
                "CVE-2017-7093", "CVE-2017-7094", "CVE-2017-7095", "CVE-2017-7096",
                "CVE-2017-7098", "CVE-2017-7099", "CVE-2017-7100", "CVE-2017-7102",
                "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7109", "CVE-2017-7111",
                "CVE-2017-7117", "CVE-2017-7120", "CVE-2017-7142", "CVE-2017-7156",
                "CVE-2017-7157");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for webkit2gtk3 openSUSE-SU-2018:0326-1 (webkit2gtk3)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes
  the following issues:

  Update to version 2.18.5:

  + Disable SharedArrayBuffers from Web API.
  + Reduce the precision of 'high' resolution time to 1ms.
  + bsc#1075419 - Security fixes: includes improvements to mitigate the
  effects of Spectre and Meltdown (CVE-2017-5753 and CVE-2017-5715).

  Update to version 2.18.4:

  + Make WebDriver implementation more spec compliant.
  + Fix a bug when trying to remove cookies before a web process is
  spawned.
  + WebKitWebDriver process no longer links to libjavascriptcoregtk.
  + Fix several memory leaks in GStreamer media backend.
  + bsc#1073654 - Security fixes: CVE-2017-13866, CVE-2017-13870,
  CVE-2017-7156, CVE-2017-13856.

  Update to version 2.18.3:

  + Improve calculation of font metrics to prevent scrollbars from being
  shown unnecessarily in some cases.
  + Fix handling of null capabilities in WebDriver implementation.
  + Security fixes: CVE-2017-13798, CVE-2017-13788, CVE-2017-13803.

  Update to version 2.18.2:

  + Fix rendering of arabic text.
  + Fix a crash in the web process when decoding GIF images.
  + Fix rendering of wind in Windy.com.
  + Fix several crashes and rendering issues.

  Update to version 2.18.1:

  + Improve performance of GIF animations.
  + Fix garbled display in GMail.
  + Fix rendering of several material design icons when using the web font.
  + Fix flickering when resizing the window in Wayland.
  + Prevent default kerberos authentication credentials from being used in
  ephemeral sessions.
  + Fix a crash when webkit_web_resource_get_data() is cancelled.
  + Correctly handle touchmove and touchend events in WebKitWebView.
  + Fix the build with enchant 2.1.1.
  + Fix the build in HPPA and Alpha.
  + Fix several crashes and rendering issues.
  + Security fixes: CVE-2017-7081, CVE-2017-7087, CVE-2017-7089,
  CVE-2017-7090, CVE-2017-7091, CVE-2017-7092, CVE-2017-7093,
  CVE-2017-7094, CVE-2017-7095, CVE-2017-7096, CVE-2017-7098,
  CVE-2017-7099, CVE-2017-7100, CVE-2017-7102, CVE-2017-7104,
  CVE-2017-7107, CVE-2017-7109, CVE-2017-7111, CVE-2017-7117,
  CVE-2017-7120, CVE-2017-7142.

  - Enable gold linker on s390/s390x on SLE15/Tumbleweed.

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");
  script_tag(name:"affected", value:"webkit2gtk3 on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18", rpm:"libjavascriptcoregtk-4_0-18~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo", rpm:"libjavascriptcoregtk-4_0-18-debuginfo~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37", rpm:"libwebkit2gtk-4_0-37~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo", rpm:"libwebkit2gtk-4_0-37-debuginfo~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-JavaScriptCore-4_0", rpm:"typelib-1_0-JavaScriptCore-4_0~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-WebKit2-4_0", rpm:"typelib-1_0-WebKit2-4_0~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-WebKit2WebExtension-4_0", rpm:"typelib-1_0-WebKit2WebExtension-4_0~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc-4", rpm:"webkit-jsc-4~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit-jsc-4-debuginfo", rpm:"webkit-jsc-4-debuginfo~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles", rpm:"webkit2gtk-4_0-injected-bundles~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk-4_0-injected-bundles-debuginfo", rpm:"webkit2gtk-4_0-injected-bundles-debuginfo~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-debugsource", rpm:"webkit2gtk3-debugsource~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-devel", rpm:"webkit2gtk3-devel~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-plugin-process-gtk2", rpm:"webkit2gtk3-plugin-process-gtk2~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"webkit2gtk3-plugin-process-gtk2-debuginfo", rpm:"webkit2gtk3-plugin-process-gtk2-debuginfo~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-32bit", rpm:"libjavascriptcoregtk-4_0-18-32bit~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libjavascriptcoregtk-4_0-18-debuginfo-32bit", rpm:"libjavascriptcoregtk-4_0-18-debuginfo-32bit~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-32bit", rpm:"libwebkit2gtk-4_0-37-32bit~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk-4_0-37-debuginfo-32bit", rpm:"libwebkit2gtk-4_0-37-debuginfo-32bit~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libwebkit2gtk3-lang", rpm:"libwebkit2gtk3-lang~2.18.5~8.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
