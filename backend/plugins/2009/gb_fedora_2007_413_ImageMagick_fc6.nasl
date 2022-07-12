###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for ImageMagick FEDORA-2007-413
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "ImageMagick(TM) is an image display and manipulation tool for the X
  Window System. ImageMagick can read and write JPEG, TIFF, PNM, GIF,
  and Photo CD image formats. It can resize, rotate, sharpen, color
  reduce, or add special effects to an image, and when finished you can
  either save the completed work in the original format or a different
  one. ImageMagick also includes command line programs for creating
  animated or transparent .gifs, creating composite images, creating
  thumbnail images, and more.

  ImageMagick is one of your choices if you need a program to manipulate
  and dis play images. If you want to develop your own applications
  which use ImageMagick code or APIs, you need to install
  ImageMagick-devel as well";

tag_affected = "ImageMagick on Fedora Core 6";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2007-April/msg00017.html");
  script_oid("1.3.6.1.4.1.25623.1.0.305664");
  script_version("$Revision: 6622 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 07:52:50 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 16:27:46 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2007-413");
  script_cve_id("CVE-2007-1797");
  script_name( "Fedora Update for ImageMagick FEDORA-2007-413");

  script_tag(name:"summary", value:"Check for the Version of ImageMagick");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora_core", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC6")
{

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick", rpm:"x86_64/ImageMagick~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-c++", rpm:"x86_64/ImageMagick-c++~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/debug/ImageMagick-debuginfo", rpm:"x86_64/debug/ImageMagick-debuginfo~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-perl", rpm:"x86_64/ImageMagick-perl~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-c++-devel", rpm:"x86_64/ImageMagick-c++-devel~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"x86_64/ImageMagick-devel", rpm:"x86_64/ImageMagick-devel~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-perl", rpm:"i386/ImageMagick-perl~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-devel", rpm:"i386/ImageMagick-devel~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-c++", rpm:"i386/ImageMagick-c++~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick-c++-devel", rpm:"i386/ImageMagick-c++-devel~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/ImageMagick", rpm:"i386/ImageMagick~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"i386/debug/ImageMagick-debuginfo", rpm:"i386/debug/ImageMagick-debuginfo~6.2.8.0~4.fc6", rls:"FC6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
