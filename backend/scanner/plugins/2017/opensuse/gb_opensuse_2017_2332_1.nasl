###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2332_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for freerdp openSUSE-SU-2017:2332-1 (freerdp)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851604");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-03 07:18:44 +0200 (Sun, 03 Sep 2017)");
  script_cve_id("CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837",
                "CVE-2017-2838", "CVE-2017-2839");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for freerdp openSUSE-SU-2017:2332-1 (freerdp)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

  - CVE-2017-2834: Out-of-bounds write in license_recv() (bsc#1050714)

  - CVE-2017-2835: Out-of-bounds write in rdp_recv_tpkt_pdu (bsc#1050712)

  - CVE-2017-2836: Rdp Client Read Server Proprietary Certificate Denial of
  Service (bsc#1050699)

  - CVE-2017-2837: Client GCC Read Server Security Data DoS (bsc#1050704)

  - CVE-2017-2838: Client License Read Product Info Denial of Service
  Vulnerability (bsc#1050708)

  - CVE-2017-2839: Client License Read Challenge Packet Denial of Service
  (bsc#1050711)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");
  script_tag(name:"affected", value:"freerdp on openSUSE Leap 42.3, openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~git.1463131968.4e66df7~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.0.0~git.1463131968.4e66df7~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.0.0~git.1463131968.4e66df7~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.0.0~git.1463131968.4e66df7~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.0.0~git.1463131968.4e66df7~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.0.0~git.1463131968.4e66df7~3.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.0.0~git.1463131968.4e66df7~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.0.0~git.1463131968.4e66df7~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.0.0~git.1463131968.4e66df7~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.0.0~git.1463131968.4e66df7~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.0.0~git.1463131968.4e66df7~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreerdp2-debuginfo", rpm:"libfreerdp2-debuginfo~2.0.0~git.1463131968.4e66df7~6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
