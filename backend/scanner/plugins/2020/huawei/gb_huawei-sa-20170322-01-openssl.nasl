# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108772");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2016-6309", "CVE-2016-7052", "CVE-2016-6304", "CVE-2016-6305", "CVE-2016-2183", "CVE-2016-6303", "CVE-2016-6302", "CVE-2016-2182", "CVE-2016-2180", "CVE-2016-2177", "CVE-2016-2178", "CVE-2016-2179", "CVE-2016-2181", "CVE-2016-6306", "CVE-2016-6307", "CVE-2016-6308");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: Sixteen OpenSSL Vulnerabilities on Some Huawei products (huawei-sa-20170322-01-openssl)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"Statem/statem.c in OpenSSL 1.1.0a does not consider memory-block movement after a realloc call.");

  script_tag(name:"insight", value:"Statem/statem.c in OpenSSL 1.1.0a does not consider memory-block movement after a realloc call, which allows remote attackers to cause a denial of service (use-after-free) or possibly execute arbitrary code via a crafted TLS session. (Vulnerability ID: HWPSIRT-2016-09065)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6309.Crypto/x509/x509_vfy.c in OpenSSL 1.0.2i allows remote attackers to cause a denial of service by triggering a CRL operation. (Vulnerability ID: HWPSIRT-2016-09078)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-7052.Multiple memory leaks in t1_lib.c in OpenSSL before 1.0.1u, 1.0.2 before 1.0.2i, and 1.1.0 before 1.1.0a allow remote attackers to cause a denial of service via large OCSP Status Request extensions. (Vulnerability ID: HWPSIRT-2016-09079)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6304.The ssl3_read_bytes function in record/rec_layer_s3.c in OpenSSL 1.1.0 before 1.1.0a allows remote attackers to cause a denial of service by triggering a zero-length record in an SSL_peek call. (Vulnerability ID: HWPSIRT-2016-09080)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6305.The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and products, have a birthday bound of approximately four billion blocks, which makes it easier for remote attackers to obtain cleartext data via a birthday attack against a long-duration encrypted session, as demonstrated by an HTTPS session using Triple DES in CBC mode, aka a 'Sweet32' attack. (Vulnerability ID: HWPSIRT-2016-09081)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2183.Integer overflow in the MDC2_Update function in crypto/mdc2/mdc2dgst.c in OpenSSL before 1.1.0 allows remote attackers to cause a denial of service. (Vulnerability ID: HWPSIRT-2016-09082)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6303.The tls_decrypt_ticket function in ssl/t1_lib.c in OpenSSL before 1.1.0 does not consider the HMAC size during validation of the ticket length, which allows remote attackers to cause a denial of service via a ticket that is too short. (Vulnerability ID: HWPSIRT-2016-09083)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6302.The BN_bn2dec function in crypto/bn/bn_print.c in OpenSSL before 1.1.0 does not properly validate division results, which allows remote attackers to cause a denial of service. (Vulnerability ID: HWPSIRT-2016-09084)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2182.The TS_OBJ_print_bio function in crypto/ts/ts_lib.c in the X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) implementation in OpenSSL through 1.0.2h allows remote attackers to cause a denial of service via a crafted time-stamp file that is mishandled by the 'openssl ts' command. (Vulnerability ID: HWPSIRT-2016-09085)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2180.OpenSSL through 1.0.2h incorrectly uses pointer arithmetic for heap-buffer boundary checks, which might allow remote attackers to cause a denial of service. (Vulnerability ID: HWPSIRT-2016-09086)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2177.The dsa_sign_setup function in crypto/dsa/dsa_ossl.c in OpenSSL through 1.0.2h does not properly ensure the use of constant-time operations, which makes it easier for local users to discover a DSA private key via a timing side-channel attack. (Vulnerability ID: HWPSIRT-2016-09087)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2178.The DTLS implementation in OpenSSL before 1.1.0 does not properly restrict the lifetime of queue entries associated with unused out-of-order messages, which allows remote attackers to cause a denial of service by maintaining many crafted DTLS sessions simultaneously. (Vulnerability ID: HWPSIRT-2016-09088)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2179.The Anti-Replay feature in the DTLS implementation in OpenSSL before 1.1.0 exist a vulnerability, which allows remote attackers to cause a denial of service. (Vulnerability ID: HWPSIRT-2016-09089)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-2181.The certificate parser in OpenSSL before 1.0.1u and 1.0.2 before 1.0.2i might allow remote attackers to cause a denial of service via crafted certificate operations. (Vulnerability ID: HWPSIRT-2016-09090)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6306.The state-machine implementation in OpenSSL 1.1.0 before 1.1.0a allocates memory before checking for an excessive length, which might allow remote attackers to cause a denial of service via crafted TLS messages. (Vulnerability ID: HWPSIRT-2016-09091)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6307.Statem/statem_dtls.c in the DTLS implementation in OpenSSL 1.1.0 before 1.1.0a allocates memory before checking for an excessive length, which might allow remote attackers to cause a denial of service via crafted DTLS messages. (Vulnerability ID: HWPSIRT-2016-09092)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2016-6308.Huawei has released software updates to fix these vulnerabilities. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"For technical details, customers are advised to check the references.");

  script_tag(name:"affected", value:"AC6005 versions V200R005C10

AC6605 versions V200R005C00 V200R005C10

AP5000 versions V200R007C10SPC300

AP5010SN-GN versions V200R005C10

AP5030DN versions V200R005C10

AP5130DN versions V200R005C10

AP6010SN-GN versions V200R005C10

AP6310SN-GN versions V200R005C10

AP6510DN-AGN versions V200R005C10

AP6610DN-AGN versions V200R005C10

AP7030DE versions V200R005C10 V200R005C20

AP7110DN-AGN versions V200R005C10

AP7110SN-GN versions V200R005C10

AP8030DN versions V200R005C10

AP8130DN versions V200R005C10

AP9330DN versions V200R005C20

AR3200 versions V200R008C10 V200R008C20

DP300 versions V500R002C00

E6000 versions V100R002C03

FusionManager versions V100R005C00

HiSTBAndroid versions Versions earlier than V600R001C00SPC066

IPC6112-D versions V100R001C10

IPC6611-Z30-I versions V100R001C00

OceanStor 9000 versions V100R001C01 V100R001C30 V300R005C00

OceanStor Backup Software versions V100R002C00

OceanStor UDS versions V100R002C00LVDF01 V1R2C01LHWS01RC3 V1R2C01LHWS01RC6

RH5885 V2 versions V100R001C01 V100R001C02

RH5885 V3 versions V100R003C01 V100R003C10

SMSC versions V300R002C90LG0005

SeMG9811 versions V300R001C01

TE30 versions V100R001C02B053SP02 V100R001C02B053SP03 V100R001C02SPC100 V100R001C02SPC100B011 V100R001C02SPC100B012 V100R001C02SPC100B013 V100R001C02SPC100B014 V100R001C02SPC100B015 V100R001C02SPC100B016 V100R001C02SPC100T V100R001C02SPC100TB010 V100R001C02SPC101T V100R001C02SPC101TB010 V100R001C02SPC102T V100R001C02SPC102TB010 V100R001C02SPC103T V100R001C02SPC103TB010 V100R001C02SPC200 V100R001C02SPC200B010 V100R001C02SPC200B011 V100R001C02SPC200T V100R001C02SPC200TB010 V100R001C02SPC201TB010 V100R001C02SPC202T V100R001C02SPC202TB010 V100R001C02SPC203T V100R001C02SPC300B010 V100R001C10 V100R001C10SPC100 V100R001C10SPC200B010 V100R001C10SPC300 V100R001C10SPC500 V100R001C10SPC600 V100R001C10SPC700B010 V100R001C10SPC800 V500R002C00SPC200 V500R002C00SPC500 V500R002C00SPC600 V500R002C00SPC700

TE40 versions V500R002C00SPC600 V500R002C00SPC700

TE60 versions V100R001C10 V500R002C00

USG9520 versions V200R001C01 V300R001C01 V300R001C20

USG9560 versions V200R001C01 V300R001C01 V300R001C20

USG9580 versions V200R001C01 V300R001C01 V300R001C20

VCM versions V100R001C10 V100R001C10SPC001 V100R001C10SPC002 V100R001C10SPC003 V100R001C10SPC004 V100R001C10SPC005 V100R001C10SPC006 V100R001C20

ViewPoint 9030 versions V100R011C02SPC100 V100R011C02SPC100B010 V100R011C03B012SP15 V100R011C03B012SP16 V100R011C03B015SP03 V100R011C03LGWL01SPC100 V100R011C03LGWL01SPC100B012 V100R011C03LGWL02SPC100T V100R011C03SPC100 V100R011C03SPC100B010 V100R011C03SPC100B011 V100R011C03SPC100B012 V100R011C03SPC100T V100R011C03SPC200 V100R011C03SPC200T V100R011C03SPC300 V100R011C03SPC400

eAPP610 versions V100R003C00

eLog versions V200R005C00SPC100 V200R005C00SPC101

eSpace 7910 versions V200R003C00

eSpace 7950 versions V200R003C00SPCf00 V200R003C30

eSpace 8950 versions V200R003C00

eSpace IAD versions V300R002C01SPCb00

eSpace U1981 versions V200R003C30

eSpace USM versions V100R001C10SPC105 V300R001C00

eSpace VCN3000 versions V100R002C00SPC100 V100R002C00SPC108 V100R002C00SPC109 V100R002C10B026 V100R002C10SPC001 V100R002C10SPC100 V100R002C10SPC100T V100R002C10SPC101 V100R002C10SPC101T V100R002C10SPC102 V100R002C10SPC102T V100R002C10SPC102TB011 V100R002C10SPC103 V100R002C10SPC103T V100R002C10SPC105T V100R002C10SPC106 V100R002C10SPC107 V100R002C10SPC107_B1253000 V100R002C10SPC108 V100R002C20B022 V100R002C20SPC001B012 V100R002C20SPC001T V100R002C20SPC100 V100R002C20SPC200 V100R002C20SPC201 V100R002C20SPC201T V100R002C20SPC201TB012

iBMC versions V100R002C10 V100R002C30 V200R002C20");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20170322-01-openssl-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
