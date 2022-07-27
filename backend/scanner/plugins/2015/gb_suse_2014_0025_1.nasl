###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_0025_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for openssl-certs SUSE-SU-2014:0025-1 (openssl-certs)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850765");
  script_version("$Revision: 12381 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:00 +0530 (Tue, 13 Oct 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for openssl-certs SUSE-SU-2014:0025-1 (openssl-certs)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl-certs'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"openssl-certs was updated with the current certificate data
  available from  mozilla.org.

  Changes:

  *

  Updated certificates to revision 1.95

  Distrust a sub-ca that issued google.com
  certificates. 'Distrusted AC DG Tresor SSL' (bnc#854367)

  Many CA updates from Mozilla:

  * new:
  CA_Disig_Root_R1:2.9.0.195.3.154.238.80.144.110.40.crt
  server auth, code signing, email signing

  * new:
  CA_Disig_Root_R2:2.9.0.146.184.136.219.176.138.193.99.crt
  server auth, code signing, email signing

  * new:
  China_Internet_Network_Information_Center_EV_Certificates_Root:2.4.72.159.0.1.crt server auth

  * changed:
  Digital_Signature_Trust_Co._Global_CA_1:2.4.54.112.21.150.cr
  t removed code signing and server auth abilities

  * changed:
  Digital_Signature_Trust_Co._Global_CA_3:2.4.54.110.211.206.c
  rt removed code signing and server auth abilities

  * new: D-TRUST_Root_Class_3_CA_2_2009:2.3.9.131.243.crt
  server auth

  * new:
  D-TRUST_Root_Class_3_CA_2_EV_2009:2.3.9.131.244.crt server
  auth

  * removed:
  Entrust.net_Premium_2048_Secure_Server_CA:2.4.56.99.185.102.
  crt

  * new:
  Entrust.net_Premium_2048_Secure_Server_CA:2.4.56.99.222.248.
  crt

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
  added code signing ability

  * new 'EE Certification Centre Root CA'

  * new 'T-TeleSec GlobalRoot Class 3'

  * revoke mis-issued intermediate CAs from TURKTRUST.");
  script_tag(name:"affected", value:"openssl-certs on SUSE Linux Enterprise Server 11 SP3");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLES11.0SP3")
{

  if ((res = isrpmvuln(pkg:"openssl-certs", rpm:"openssl-certs~1.95~0.4.1", rls:"SLES11.0SP3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
