###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_0473_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for quagga openSUSE-SU-2018:0473-1 (quagga)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851705");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-02-20 08:44:45 +0100 (Tue, 20 Feb 2018)");
  script_cve_id("CVE-2017-16227", "CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380",
                "CVE-2018-5381");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for quagga openSUSE-SU-2018:0473-1 (quagga)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for quagga fixes the following issues:

  - CVE-2017-16227: Fixed bgpd DoS via specially crafted BGP UPDATE messages
  (boo#1065641)

  - CVE-2018-5378: Fixed bgpd bounds check issue via attribute length
  (Quagga-2018-0543, boo#1079798)

  - CVE-2018-5379: Fixed bgpd double free when processing UPDATE message
  (Quagga-2018-1114, boo#1079799)

  - CVE-2018-5380: Fixed bgpd code-to-string conversion tables overrun
  (Quagga-2018-1550, boo#1079800)

  - CVE-2018-5381: Fixed bgpd infinite loop on certain invalid OPEN messages
  (Quagga-2018-1975, boo#1079801)");
  script_tag(name:"affected", value:"quagga on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-02/msg00037.html");
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

  if ((res = isrpmvuln(pkg:"libfpm_pb0", rpm:"libfpm_pb0~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfpm_pb0-debuginfo", rpm:"libfpm_pb0-debuginfo~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libospf0", rpm:"libospf0~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libospf0-debuginfo", rpm:"libospf0-debuginfo~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libospfapiclient0", rpm:"libospfapiclient0~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libospfapiclient0-debuginfo", rpm:"libospfapiclient0-debuginfo~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libquagga_pb0", rpm:"libquagga_pb0~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libquagga_pb0-debuginfo", rpm:"libquagga_pb0-debuginfo~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzebra1", rpm:"libzebra1~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libzebra1-debuginfo", rpm:"libzebra1-debuginfo~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga", rpm:"quagga~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-debuginfo", rpm:"quagga-debuginfo~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-debugsource", rpm:"quagga-debugsource~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"quagga-devel", rpm:"quagga-devel~1.1.1~18.3.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
