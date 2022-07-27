###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4151_1_deprecated.nasl 13940 2019-02-28 14:10:38Z cfischer $
#
# SuSE Update for pdns-recursor openSUSE-SU-2018:4151-1 (pdns-recursor)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852194");
  script_version("$Revision: 13940 $");
  script_tag(name:"deprecated", value:TRUE);
  script_cve_id("CVE-2018-10851", "CVE-2018-14626", "CVE-2018-14644");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-28 15:10:38 +0100 (Thu, 28 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-12-18 07:42:09 +0100 (Tue, 18 Dec 2018)");
  script_name("SuSE Update for pdns-recursor openSUSE-SU-2018:4151-1 (pdns-recursor)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00045.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns-recursor'
  package(s) announced via the openSUSE-SU-2018:4151_1 advisory.
  This NVT has been replaced by OID: 1.3.6.1.4.1.25623.1.0.814572");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pdns-recursor fixes the following issues:

  Security issues fixed:

  - CVE-2018-10851: Fixed denial of service via crafted zone record or
  crafted answer (bsc#1114157).

  - CVE-2018-14644: Fixed denial of service via crafted query for meta-types
  (bsc#1114170).

  - CVE-2018-14626: Fixed packet cache pollution via crafted query
  (bsc#1114169).


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1564=1");

  script_tag(name:"affected", value:"pdns-recursor on openSUSE Leap 42.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in OID: 1.3.6.1.4.1.25623.1.0.814572
include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"pdns-recursor", rpm:"pdns-recursor~4.0.5~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pdns-recursor-debuginfo", rpm:"pdns-recursor-debuginfo~4.0.5~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pdns-recursor-debugsource", rpm:"pdns-recursor-debugsource~4.0.5~9.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
