###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_1860-01_libtasn1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for libtasn1 RHSA-2017:1860-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871853");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-04 12:47:20 +0530 (Fri, 04 Aug 2017)");
  script_cve_id("CVE-2015-2806", "CVE-2015-3622");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libtasn1 RHSA-2017:1860-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtasn1'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Libtasn1 is a library that provides Abstract
  Syntax Notation One (ASN.1, as specified by the X.680 ITU-T recommendation)
  parsing and structures management, and Distinguished Encoding Rules (DER, as per
  X.690) encoding and decoding functions. The following packages have been
  upgraded to a later upstream version: libtasn1 (4.10). (BZ#1360639) Security
  Fix(es): * A heap-based buffer overflow flaw was found in the way the libtasn1
  library decoded certain DER-encoded inputs. A specially crafted DER-encoded
  input could cause an application using libtasn1 to perform an invalid read,
  causing the application to crash. (CVE-2015-3622) * A stack-based buffer
  overflow was found in the way libtasn1 decoded certain DER encoded data. An
  attacker could use this flaw to crash an application using the libtasn1 library.
  (CVE-2015-2806) Additional Changes: For detailed information on changes in this
  release, see the Red Hat Enterprise Linux 7.4 Release Notes linked from the
  References section.");
  script_tag(name:"affected", value:"libtasn1 on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-August/msg00007.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libtasn1", rpm:"libtasn1~4.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-debuginfo", rpm:"libtasn1-debuginfo~4.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtasn1-devel", rpm:"libtasn1-devel~4.10~1.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
