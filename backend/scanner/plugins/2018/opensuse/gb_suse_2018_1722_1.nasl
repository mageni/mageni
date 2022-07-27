###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_1722_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for python-python-gnupg openSUSE-SU-2018:1722-1 (python-python-gnupg)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852024");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-12020");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-26 06:35:13 +0200 (Fri, 26 Oct 2018)");
  script_name("SuSE Update for python-python-gnupg openSUSE-SU-2018:1722-1 (python-python-gnupg)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-06/msg00033.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-python-gnupg'
  package(s) announced via the openSUSE-SU-2018:1722_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-python-gnupg to version 0.4.3 fixes the following
  issues:

  The following security vulnerabilities were addressed:

  - Sanitize diagnostic output of the original file name in verbose mode
  (CVE-2018-12020 boo#1096745)

  The following other changes were made:

  - Add --no-verbose to the gpg command line, in case verbose is specified
  is gpg.conf.

  - Add expect_passphrase password for use on GnuPG  = 2.1 when passing
  passphrase to gpg via pinentry

  - Provide a trust_keys method to allow setting the trust level for keys

  - When the gpg executable is not found, note the path used in the
  exception message

  - Make error messages more informational


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-646=1");

  script_tag(name:"affected", value:"python-python-gnupg on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"python2-python-gnupg", rpm:"python2-python-gnupg~0.4.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python3-python-gnupg", rpm:"python3-python-gnupg~0.4.3~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
