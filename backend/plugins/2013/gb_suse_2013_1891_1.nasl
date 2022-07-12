###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2013_1891_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for ca-certificates-mozilla openSUSE-SU-2013:1891-1 (ca-certificates-mozilla)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850560");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-12-17 12:05:15 +0530 (Tue, 17 Dec 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:P");
  script_name("SuSE Update for ca-certificates-mozilla openSUSE-SU-2013:1891-1 (ca-certificates-mozilla)");
  script_tag(name:"affected", value:"ca-certificates-mozilla on openSUSE 13.1, openSUSE 12.3,
  openSUSE 12.2");
  script_tag(name:"insight", value:"The Mozilla CA certificates package was updated to match
  the current Mozilla revision 1.95 of certdata.txt.

  It blacklists some misused certificate authorities, adds
  some new and adjusts some others.

  On openSUSE 13.1 a problem with names was also fixed.

  * distrust: AC DG Tresor SSL (bnc#854367)

  * new:
  CA_Disig_Root_R1:2.9.0.195.3.154.238.80.144.110.40.crt
  server auth, code signing, email signing

  * new:
  CA_Disig_Root_R2:2.9.0.146.184.136.219.176.138.193.99.crt
  server auth, code signing, email signing

  * new:
  China_Internet_Network_Information_Center_EV_Certificates_Root:2.4.72.159.0.1.crt server auth

  * changed:
  Digital_Signature_Trust_Co._Global_CA_1:2.4.54.112.21.150.crt
  removed code signing and server auth abilities

  * changed:
  Digital_Signature_Trust_Co._Global_CA_3:2.4.54.110.211.206.crt
  removed code signing and server auth abilities

  * new: D-TRUST_Root_Class_3_CA_2_2009:2.3.9.131.243.crt
  server auth

  * new: D-TRUST_Root_Class_3_CA_2_EV_2009:2.3.9.131.244.crt
  server auth

  * removed:
  Equifax_Secure_eBusiness_CA_2:2.4.55.112.207.181.crt

  * new: PSCProcert:2.1.11.crt server auth, code signing,
  email signing

  * new:
  Swisscom_Root_CA_2:2.16.30.158.40.232.72.242.229.239.195.124
  .74.30.90.24.103.182.crt server auth, code signing, email
  signing

  * new:
  Swisscom_Root_EV_CA_2:2.17.0.242.250.100.226.116.99.211.141.
  253.16.29.4.31.118.202.88.crt server auth, code signing

  * changed:
  TC_TrustCenter_Universal_CA_III:2.14.99.37.0.1.0.2.20.141.51
  .21.2.228.108.244.crt removed all abilities

  * new:
  TURKTRUST_Certificate_Services_Provider_Root_2007:2.1.1.crt
  server auth, code signing

  * changed: TWCA_Root_Certification_Authority:2.1.1.crt
  added code signing ability");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'ca-certificates-mozilla'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE12\.3|openSUSE12\.2|openSUSE13\.1)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.3")
{

  if ((res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~1.95~3.4.1", rls:"openSUSE12.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~1.95~8.12.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "openSUSE13.1")
{

  if ((res = isrpmvuln(pkg:"ca-certificates-mozilla", rpm:"ca-certificates-mozilla~1.95~3.4.1", rls:"openSUSE13.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
