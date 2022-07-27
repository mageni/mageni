###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for ImageMagick CESA-2012:0544 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-May/018615.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881116");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:10:56 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4167", "CVE-2012-0247", "CVE-2012-0248", "CVE-2012-0259",
                "CVE-2012-0260", "CVE-2012-1798");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for ImageMagick CESA-2012:0544 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ImageMagick'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"ImageMagick on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"ImageMagick is an image display and manipulation tool for the X Window
  System that can read and write multiple image formats.

  A flaw was found in the way ImageMagick processed images with malformed
  Exchangeable image file format (Exif) metadata. An attacker could create a
  specially-crafted image file that, when opened by a victim, would cause
  ImageMagick to crash or, potentially, execute arbitrary code.
  (CVE-2012-0247)

  A denial of service flaw was found in the way ImageMagick processed images
  with malformed Exif metadata. An attacker could create a specially-crafted
  image file that, when opened by a victim, could cause ImageMagick to enter
  an infinite loop. (CVE-2012-0248)

  It was found that ImageMagick utilities tried to load ImageMagick
  configuration files from the current working directory. If a user ran an
  ImageMagick utility in an attacker-controlled directory containing a
  specially-crafted ImageMagick configuration file, it could cause the
  utility to execute arbitrary code. (CVE-2010-4167)

  An integer overflow flaw was found in the way ImageMagick processed
  certain Exif tags with a large components count. An attacker could create
  a specially-crafted image file that, when opened by a victim, could cause
  ImageMagick to access invalid memory and crash. (CVE-2012-0259)

  A denial of service flaw was found in the way ImageMagick decoded certain
  JPEG images. A remote attacker could provide a JPEG image with
  specially-crafted sequences of RST0 up to RST7 restart markers (used to
  indicate the input stream to be corrupted), which once processed by
  ImageMagick, would cause it to consume excessive amounts of memory and CPU
  time. (CVE-2012-0260)

  An out-of-bounds buffer read flaw was found in the way ImageMagick
  processed certain TIFF image files. A remote attacker could provide a TIFF
  image with a specially-crafted Exif IFD value (the set of tags for
  recording Exif-specific attribute information), which once opened by
  ImageMagick, would cause it to crash. (CVE-2012-1798)

  Red Hat would like to thank CERT-FI for reporting CVE-2012-0259,
  CVE-2012-0260, and CVE-2012-1798. CERT-FI acknowledges Aleksis Kauppinen,
  Joonas Kuorilehto, Tuomas Parttimaa and Lasse Ylivainio of Codenomicon's
  CROSS project as the original reporters.

  Users of ImageMagick are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  instances of ImageMagick must be restarted for this update to take effect.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"ImageMagick", rpm:"ImageMagick~6.5.4.7~6.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++", rpm:"ImageMagick-c++~6.5.4.7~6.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-c++-devel", rpm:"ImageMagick-c++-devel~6.5.4.7~6.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-devel", rpm:"ImageMagick-devel~6.5.4.7~6.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-doc", rpm:"ImageMagick-doc~6.5.4.7~6.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ImageMagick-perl", rpm:"ImageMagick-perl~6.5.4.7~6.el6_2", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
