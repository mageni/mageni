###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1310_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for librsvg openSUSE-SU-2018:1310-1 (librsvg)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851747");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-05-17 05:37:19 +0200 (Thu, 17 May 2018)");
  script_cve_id("CVE-2018-1000041");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for librsvg openSUSE-SU-2018:1310-1 (librsvg)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'librsvg'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");
  script_tag(name:"insight", value:"This update for librsvg fixes the following issues:

  - CVE-2018-1000041: Input validation issue could lead to credentials leak.
  (bsc#1083232)

  Update to version 2.40.20:

  + Except for emergencies, this will be the LAST RELEASE of the
  librsvg-2.40.x series.  We are moving to 2.41, which is vastly
  improved over the 2.40 series.  The API/ABI there remain unchanged, so
  we strongly encourage you to upgrade your sources and binaries to
  librsvg-2.41.x.
  + bgo#761175 - Allow masks and clips to reuse a node being drawn.
  + Don't access the file system when deciding whether to load a remote
  file with a UNC path for a paint server (i.e. don't try to load it at
  all).
  + Vistual Studio: fixed and integrated introspection builds, so
  introspection data is built directly from the Visual Studio project
  (Chun-wei Fan).
  + Visual Studio: We now use HIGHENTROPYVA linker option on x64 builds,
  to enhance the security of built binaries (Chun-wei Fan).
  + Fix generation of Vala bindings when compiling in read-only source
  directories (Emmanuele Bassi).

  Update to version 2.40.19:

  + bgo#621088: Using text objects as clipping paths is now supported.
  + bgo#587721: Fix rendering of text elements with transformations
  (Massimo).
  + bgo#777833 - Fix memory leaks when an RsvgHandle is disposed before
  being closed (Philip Withnall).
  + bgo#782098 - Don't pass deprecated options to gtk-doc (Ting-Wei Lan).
  + bgo#786372 - Fix the default for the 'type' attribute of the  style
  element.
  + bgo#785276 - Don't crash on single-byte files.
  + bgo#634514: Don't render unknown elements and their sub-elements.
  + bgo#777155 - Ignore patterns that have close-to-zero dimensions.
  + bgo#634324 - Fix Gaussian blurs with negative scaling.
  + Fix the  switch  element  it wasn't working at all.
  + Fix loading when rsvg_handle_write() is called one byte at a time.
  + bgo#787895 - Fix incorrect usage of libxml2.  Thanks to Nick
  Wellnhofer for advice on this.
  + Backported the test suite machinery from the master branch (Chun-wei
  Fan, Federico Mena).
  + We now require Pango 1.38.0 or later (released in 2015).
  + We now require libxml2 2.9.0 or later (released in 2012).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-466=1");
  script_tag(name:"affected", value:"librsvg on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-05/msg00077.html");
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

  if ((res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg", rpm:"gdk-pixbuf-loader-rsvg~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-debuginfo", rpm:"gdk-pixbuf-loader-rsvg-debuginfo~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librsvg-2-2", rpm:"librsvg-2-2~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librsvg-2-2-debuginfo", rpm:"librsvg-2-2-debuginfo~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librsvg-debugsource", rpm:"librsvg-debugsource~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librsvg-devel", rpm:"librsvg-devel~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsvg-view", rpm:"rsvg-view~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"rsvg-view-debuginfo", rpm:"rsvg-view-debuginfo~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"typelib-1_0-Rsvg-2_0", rpm:"typelib-1_0-Rsvg-2_0~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-32bit", rpm:"gdk-pixbuf-loader-rsvg-32bit~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gdk-pixbuf-loader-rsvg-debuginfo-32bit", rpm:"gdk-pixbuf-loader-rsvg-debuginfo-32bit~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librsvg-2-2-32bit", rpm:"librsvg-2-2-32bit~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"librsvg-2-2-debuginfo-32bit", rpm:"librsvg-2-2-debuginfo-32bit~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"svg-thumbnailer", rpm:"svg-thumbnailer~2.40.20~15.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
