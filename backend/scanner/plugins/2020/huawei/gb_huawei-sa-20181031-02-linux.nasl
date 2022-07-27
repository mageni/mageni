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
  script_oid("1.3.6.1.4.1.25623.1.0.108802");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2018-5390");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: SegmentSmack Vulnerability in Linux Kernel (huawei-sa-20181031-02-linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a DoS vulnerability in the Linux Kernel versions 4.9+ and supported versions known as a SegmentSmack attack.");

  script_tag(name:"insight", value:"There is a DoS vulnerability in the Linux Kernel versions 4.9+ and supported versions known as a SegmentSmack attack. Remote attackers may send TCP packets to Linux kernel to make it calls the very expensive functions tcp_collapse_ofo_queue() and tcp_prune_ofo_queue() of the affected device which can lead to a denial of service. Maintaining the denial of service condition requires continuous two-way TCP sessions to a reachable open port. Thus, the attacks cannot be performed using spoofed IP addresses. (Vulnerability ID: HWPSIRT-2018-08114)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2018-5390.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"A remote attacker may be able to trigger a denial-of-service condition.");

  script_tag(name:"affected", value:"ALP-AL00B versions Versions earlier than 9.0.0.125(C00E81R2P20T8)

ALP-L09 versions Versions earlier than 8.0.0.152(C432)

ALP-L29 versions Versions earlier than 8.0.0.140(C185) Versions earlier than 8.0.0.142(C636)

Anne-AL00 versions Versions earlier than 8.0.0.168(C00)

Atomu-L03 versions Versions earlier than 8.0.0.144(C605CUSTC605D1)

Atomu-L11 versions Versions earlier than 8.0.0.144(C782CUSTC782D1)

Atomu-L21 versions Versions earlier than 8.0.0.142(C432CUSTC432D1)

Atomu-L23 versions Versions earlier than 8.0.0.146(C605CUSTC605D1)

Atomu-L29A versions Versions earlier than 8.0.0.137(C432CUSTC432D1) Versions earlier than 8.0.0.142(C185CUSTC185D1) Versions earlier than 8.0.0.142(C461CUSTC461D1) Versions earlier than 8.0.0.162(C636CUSTC636D1)

Atomu-L41 versions Versions earlier than 8.0.0.143(C461CUSTC461D1)

Atomu-L42 versions Versions earlier than 8.0.0.143(C636CUSTC636D1)

BLA-AL00B versions Versions earlier than 9.0.0.125(C00E83R2P15T8)

BLA-L09C versions Versions earlier than 8.0.0.139(C185) Versions earlier than 8.0.0.140(C605)

BLA-L29C versions Versions earlier than 8.0.0.140(C605) Versions earlier than 8.0.0.144(C185) Versions earlier than 8.0.0.144(C636) Versions earlier than 8.0.0.151(C635) Versions earlier than 8.0.0.157(C432)

Charlotte-L09C versions Versions earlier than 8.1.0.154(C185) Versions earlier than 8.1.0.155(C605) Versions earlier than 8.1.0.157(C432)

Charlotte-L29C versions Versions earlier than 8.1.0.154(C185) Versions earlier than 8.1.0.155(C636) Versions earlier than 8.1.0.159(C432) Versions earlier than 8.1.0.161(C605)

Delhi-L42 versions Versions earlier than C185B123 Versions earlier than C432B136

Duke-L09 versions C10B187 C432B189 C636B189

Emily-AL00A versions 8.1.0.152D(C00) 8.1.0.165D(C00) 8.1.0.167(C00)

Emily-L09C versions Versions earlier than 9.0.0.159(C185E2R1P12T8) Versions earlier than 9.0.0.160(C432E7R1P11T8) Versions earlier than 9.0.0.161(C605E2R1P11T8)

Emily-L29C versions Versions earlier than 8.1.0.154(C635) Versions earlier than 8.1.0.154(C635) Versions earlier than 9.0.0.159(C185E2R1P12T8) Versions earlier than 9.0.0.159(C461E2R1P11T8) Versions earlier than 9.0.0.160(C432E7R1P11T8) Versions earlier than 9.0.0.161(C605E2R1P12T8) Versions earlier than 9.0.0.168(C636E7R1P13T8)

EulerOS versions 2.1.11 2.1.6 2.2.RC3 2.2.RC5 V200R002C10 V200R002C20 V200R003C00 V200R003C00SPC200 V200R003C00SPC503 V200R003C00SPC509 V200R003C00SPC609 V200R005C00 V200R005C00SPC100 V200R005C00SPC200 V200R005C00SPC300 V200R005C00SPC310 V200R005C00SPC317 V200R005C00SPC318 V200R007C00SPC200

FusionCompute versions 6.3.0 6.3.RC1

FusionSphere OpenStack versions V100R006C00 V100R006C00RC1 V100R006C00RC2 V100R006C00U1 V100R006C10 V100R006C10RC1 V100R006C10RC1B060 V100R006C10RC2 V100R006C10SPC002B010 V100R006C10SPC100 V100R006C10SPC110 V100R006C10SPC200 V100R006C10SPC200B030 V100R006C10SPC301 V100R006C10SPC500 V100R006C10SPC530 V100R006C10SPC600 V100R006C10U10 V100R006C10U20 V100R006C30 V100R006C30SPC100

HUAWEI P20 versions 6.0.1.3(C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 8.1.0.167(SP1C00) Versions earlier than 9.0.0.125(C00E76R1P21T8)

HUAWEI P20 Pro versions 8.1.0.176(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00)

HUAWEI Y6 2018 versions Versions earlier than 8.0.0.142(C432CUSTC432D1) Versions earlier than 8.0.0.143(C185CUSTC185D1) Versions earlier than 8.0.0.143(C185CUSTC185D1) Versions earlier than 8.0.0.144(C636CUSTC636D1)

HUAWEI Y6 Prime 2018 versions Versions earlier than 8.0.0.142(C569CUSTC569D1) Versions earlier than 8.0.0.143(C461CUSTC461D1) Versions earlier than 8.0.0.144(C185CUSTC185D1)

HUAWEI Y7 2018 versions Versions earlier than 8.0.0.139(C432CUSTC432D1) Versions earlier than 8.0.0.139(C432CUSTC432D1) Versions earlier than 8.0.0.142(C185CUSTC185D1) Versions earlier than 8.0.0.150(C569CUSTC569D1) Versions earlier than 8.0.0.153(C185CUSTC185D1) Versions earlier than 8.0.0.153(C605CUSTC605D1 Versions earlier than 8.0.0.160(C782CUSTC782D1)

HUAWEI Y7 Prime 2018 versions Versions earlier than 8.0.0.135(C432CUSTC432D1) Versions earlier than 8.0.0.147(C185CUSTC185D1)

HUAWEI Y7 Pro 2018 versions Versions earlier than 8.0.0.146(C636CUSTC636D1)

Jimmy-AL00A versions Versions earlier than C00B172

Jimmy-L22HN versions Versions earlier than C432B136

LON-L29D versions C721B192

London-AL40B versions Versions earlier than 8.0.0.215(C00)

London-L22 versions Versions earlier than 8.0.0.147(C636CUSTC636D1)

London-L29 versions Versions earlier than 8.0.0.135(C461CUSTC461D1) Versions earlier than 8.0.0.137(C432CUSTC432D1) Versions earlier than 8.0.0.144(C185CUSTC185D1) Versions earlier than 8.0.0.145(C636CUSTC636D1)

Selina-L02 versions Versions earlier than C432B159

Toronto-L01 versions Versions earlier than C464B164CUSTC464D001

Toronto-L03 versions Versions earlier than C469B189CUSTC469D001

Toronto-L21 versions Versions earlier than C10B176CUSTC10D001 Versions earlier than C432B181CUSTC432D001 Versions earlier than C569B180CUSTC569D001

Toronto-L22 versions Versions earlier than C636B188CUSTC636D001

Toronto-L23 versions Versions earlier than C469B190CUSTC469D001

Honor 8X versions Versions earlier than 9.0.1.156(C00E21R2P5T8)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20181031-02-linux-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
