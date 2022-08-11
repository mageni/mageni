###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_3147_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for gstreamer-0_10-plugins-bad openSUSE-SU-2016:3147-1 (gstreamer-0_10-plugins-bad)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851456");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-12-15 06:04:20 +0100 (Thu, 15 Dec 2016)");
  script_cve_id("CVE-2016-9445", "CVE-2016-9446");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for gstreamer-0_10-plugins-bad openSUSE-SU-2016:3147-1 (gstreamer-0_10-plugins-bad)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-0_10-plugins-bad'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for gstreamer-0_10-plugins-bad fixes the following issues:

  - Maliciously crafted VMnc files (VMWare video format) could lead to
  crashes (CVE-2016-9445, CVE-2016-9446, boo#1010829).

  - Maliciously crafted NSF files (NES sound format) could lead to arbitrary
  code execution (CESA-2016-0001, boo#1010514). Therefore for security
  reasons the NSF plugin has been removed from the package.");
  script_tag(name:"affected", value:"gstreamer-0_10-plugins-bad on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad", rpm:"gstreamer-0_10-plugins-bad~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-debuginfo", rpm:"gstreamer-0_10-plugins-bad-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-debugsource", rpm:"gstreamer-0_10-plugins-bad-debugsource~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-devel", rpm:"gstreamer-0_10-plugins-bad-devel~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-doc", rpm:"gstreamer-0_10-plugins-bad-doc~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasecamerabinsrc-0_10-23", rpm:"libgstbasecamerabinsrc-0_10-23~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasecamerabinsrc-0_10-23-debuginfo", rpm:"libgstbasecamerabinsrc-0_10-23-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasevideo-0_10-23", rpm:"libgstbasevideo-0_10-23~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasevideo-0_10-23-debuginfo", rpm:"libgstbasevideo-0_10-23-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstcodecparsers-0_10-23", rpm:"libgstcodecparsers-0_10-23~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstcodecparsers-0_10-23-debuginfo", rpm:"libgstcodecparsers-0_10-23-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstphotography-0_10-23", rpm:"libgstphotography-0_10-23~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstphotography-0_10-23-debuginfo", rpm:"libgstphotography-0_10-23-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstsignalprocessor-0_10-23", rpm:"libgstsignalprocessor-0_10-23~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstsignalprocessor-0_10-23-debuginfo", rpm:"libgstsignalprocessor-0_10-23-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstvdp-0_10-23", rpm:"libgstvdp-0_10-23~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstvdp-0_10-23-debuginfo", rpm:"libgstvdp-0_10-23-debuginfo~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-lang", rpm:"gstreamer-0_10-plugins-bad-lang~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-32bit", rpm:"gstreamer-0_10-plugins-bad-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-0_10-plugins-bad-debuginfo-32bit", rpm:"gstreamer-0_10-plugins-bad-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasecamerabinsrc-0_10-23-32bit", rpm:"libgstbasecamerabinsrc-0_10-23-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasecamerabinsrc-0_10-23-debuginfo-32bit", rpm:"libgstbasecamerabinsrc-0_10-23-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasevideo-0_10-23-32bit", rpm:"libgstbasevideo-0_10-23-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstbasevideo-0_10-23-debuginfo-32bit", rpm:"libgstbasevideo-0_10-23-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstcodecparsers-0_10-23-32bit", rpm:"libgstcodecparsers-0_10-23-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstcodecparsers-0_10-23-debuginfo-32bit", rpm:"libgstcodecparsers-0_10-23-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstphotography-0_10-23-32bit", rpm:"libgstphotography-0_10-23-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstphotography-0_10-23-debuginfo-32bit", rpm:"libgstphotography-0_10-23-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstsignalprocessor-0_10-23-32bit", rpm:"libgstsignalprocessor-0_10-23-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstsignalprocessor-0_10-23-debuginfo-32bit", rpm:"libgstsignalprocessor-0_10-23-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstvdp-0_10-23-32bit", rpm:"libgstvdp-0_10-23-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libgstvdp-0_10-23-debuginfo-32bit", rpm:"libgstvdp-0_10-23-debuginfo-32bit~0.10.23~15.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
