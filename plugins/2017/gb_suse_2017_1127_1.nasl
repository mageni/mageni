###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1127_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libosip2 openSUSE-SU-2017:1127-1 (libosip2)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851542");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-04-29 07:16:48 +0200 (Sat, 29 Apr 2017)");
  script_cve_id("CVE-2016-10324", "CVE-2016-10325", "CVE-2016-10326", "CVE-2017-7853");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libosip2 openSUSE-SU-2017:1127-1 (libosip2)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libosip2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for libosip2 fixes the following issues:

  Changes in libosip2:

  - CVE-2017-7853: In libosip2 in GNU 5.0.0, a malformed SIP message can
  lead to a heap buffer overflow in the msg_osip_body_parse() function
  defined in osipparser2/osip_message_parse.c, resulting in a remote DoS.
  (boo#1034570)

  - CVE-2016-10326: In libosip2 in GNU oSIP 4.1.0, a malformed SIP message
  can lead to a heap buffer overflow in the osip_body_to_str() function
  defined in osipparser2/osip_body.c, resulting in a remote DoS.
  (boo#1034571)

  - CVE-2016-10325: In libosip2 in GNU oSIP 4.1.0, a malformed SIP message
  can lead to a heap buffer overflow in the _osip_message_to_str()
  function defined in osipparser2/osip_message_to_str.c, resulting in a
  remote DoS. (boo#1034572)

  - CVE-2016-10324: In libosip2 in GNU oSIP 4.1.0, a malformed SIP message
  can lead to a heap buffer overflow in the osip_clrncpy() function
  defined in osipparser2/osip_port.c. (boo#1034574)");
  script_tag(name:"affected", value:"libosip2 on openSUSE Leap 42.2, openSUSE Leap 42.1");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"libosip2", rpm:"libosip2~4.1.0~5.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libosip2-debuginfo", rpm:"libosip2-debuginfo~4.1.0~5.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libosip2-debugsource", rpm:"libosip2-debugsource~4.1.0~5.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libosip2-devel", rpm:"libosip2-devel~4.1.0~5.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.1")
{

  if ((res = isrpmvuln(pkg:"libosip2", rpm:"libosip2~4.1.0~5.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libosip2-debuginfo", rpm:"libosip2-debuginfo~4.1.0~5.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libosip2-debugsource", rpm:"libosip2-debugsource~4.1.0~5.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libosip2-devel", rpm:"libosip2-devel~4.1.0~5.1", rls:"openSUSELeap42.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
