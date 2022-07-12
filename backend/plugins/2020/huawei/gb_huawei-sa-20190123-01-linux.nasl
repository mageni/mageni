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
  script_oid("1.3.6.1.4.1.25623.1.0.108793");
  script_version("2020-06-06T12:09:29+0000");
  script_tag(name:"last_modification", value:"2020-06-08 12:34:35 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-05 08:17:40 +0000 (Fri, 05 Jun 2020)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2018-5391");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Huawei Data Communication: FragmentSmack Vulnerability in Linux Kernel (huawei-sa-20190123-01-linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Huawei");
  script_dependencies("gb_huawei_vrp_network_device_consolidation.nasl");
  script_mandatory_keys("huawei/vrp/detected");

  script_tag(name:"summary", value:"There is a DoS vulnerability in the Linux Kernel versions 3.9+ known as a FragmentSmack attack.");

  script_tag(name:"insight", value:"There is a DoS vulnerability in the Linux Kernel versions 3.9+ known as a FragmentSmack attack. Remote attackers could send fragmented IPv4 or IPv6 packets to the affected device to trigger time and calculation reassembly algorithms that could consume excessive CPU resources, resulting in a DoS condition. (Vulnerability ID: HWPSIRT-2018-08115)This vulnerability has been assigned a Common Vulnerabilities and Exposures (CVE) ID: CVE-2018-5391.Huawei has released software updates to fix this vulnerability. This advisory is available in the linked references.");

  script_tag(name:"impact", value:"A remote attacker may be able to trigger a denial-of-service condition.");

  script_tag(name:"affected", value:"Anne-AL00 versions Versions earlier than 8.0.0.168(C00)

Atomu-AL10B versions Versions earlier than 8.0.0.195(C00)

Atomu-L03 versions Versions earlier than 8.0.0.144(C605CUSTC605D1) Versions earlier than 8.0.0.144(C605CUSTC605D1)

Atomu-L11 versions Versions earlier than 8.0.0.144(C782CUSTC782D1) Versions earlier than 8.0.0.144(C782CUSTC782D1)

Atomu-L21 versions Versions earlier than 8.0.0.140(C432CUSTC432D1) Versions earlier than 8.0.0.142(C432CUSTC432D1)

Atomu-L23 versions Versions earlier than 8.0.0.144(C605CUSTC605D1) Versions earlier than 8.0.0.146(C605CUSTC605D1)

Atomu-L29A versions Versions earlier than 8.0.0.137(C432CUSTC432D1) Versions earlier than 8.0.0.137(C432CUSTC432D1) Versions earlier than 8.0.0.142(C185CUSTC185D1) Versions earlier than 8.0.0.142(C185CUSTC185D1) Versions earlier than 8.0.0.142(C461CUSTC461D1) Versions earlier than 8.0.0.142(C461CUSTC461D1) Versions earlier than 8.0.0.162(C636CUSTC636D1) Versions earlier than 8.0.0.162(C636CUSTC636D1)

Atomu-L41 versions Versions earlier than 8.0.0.143(C461CUSTC461D1) Versions earlier than 8.0.0.143(C461CUSTC461D1)

Atomu-L42 versions Versions earlier than 8.0.0.143(C636CUSTC636D1) Versions earlier than 8.0.0.143(C636CUSTC636D1)

B525s-23a versions Versions earlier than TCPU-V100R001B190D65SP00C00 Versions earlier than TCPU-V100R001B190D65SP00C00 Versions earlier than TCPU-V100R001B190D65SP00C00 Versions earlier than TCPU-V100R001B190D65SP00C00 Versions earlier than TCPU-V800R001B191D11SP00C00 Versions earlier than TCPU-V800R001B191D11SP00C00 Versions earlier than TCPU-V800R001B191D11SP00C00 Versions earlier than TCPU-V800R001B191D11SP00C00 Versions earlier than TCPU-V800R001B191D11SP00C00

BLA-A09 versions Versions earlier than 8.0.0.127(C567) Versions earlier than 8.0.0.127(C567) Versions earlier than 8.0.0.127(C567) Versions earlier than 8.0.0.127(C567)

BLA-L09C versions Versions earlier than 9.0.0.159(C185E2R1P13T8) Versions earlier than 9.0.0.160(C605E2R1P12T8) Versions earlier than 9.0.0.161(C432E4R1P11T8)

BLA-L29C versions Versions earlier than 8.0.0.151(C635) Versions earlier than 9.0.0.159(C185E2R1P13T8) Versions earlier than 9.0.0.159(C636E2R1P13T8) Versions earlier than 9.0.0.160(C605E2R1P12T8) Versions earlier than 9.0.0.161(C432E4R1P11T8)

Berkeley-AL20 versions Versions earlier than 8.0.0.202(C00GT)

Berkeley-L09 versions Versions earlier than 8.0.0.169(C636)

Cameron-AL09A versions Versions earlier than 8.0.0.187(C185) Versions earlier than 8.0.0.190(C432)

Cameron-W09A versions Versions earlier than 8.0.0.185(TWNC636)

Cannes-AL10 versions Versions earlier than C00B386

Charlotte-L09C versions Versions earlier than 9.0.0.159(C185E4R1P11T8) Versions earlier than 9.0.0.161(C605E2R1P9T8) Versions earlier than 9.0.0.163(C432E5R1P9T8)

Charlotte-L29C versions Versions earlier than 9.0.0.159(C185E4R1P11T8) Versions earlier than 9.0.0.161(C605E2R1P11T8) Versions earlier than 9.0.0.163(C432E5R1P9T8) Versions earlier than 9.0.0.168(C636E2R1P12T8)

E5785Lh-92a versions Versions earlier than TCPU-V200R001B191D63SP00C00 Versions earlier than TCPU-V200R001B191D63SP00C00

E5787Ph versions Versions earlier than -67aTCPU-V200R001B191D63SP00C00

E5787Ph-92a versions Versions earlier than TCPU-V200R001B190D61SP00C00

Emily-L09C versions Versions earlier than 9.0.0.159(C185E2R1P12T8) Versions earlier than 9.0.0.160(C432E7R1P11T8) Versions earlier than 9.0.0.161(C605E2R1P11T8)

Emily-L29C versions Versions earlier than 8.1.0.135(C635) Versions earlier than 8.1.0.154(C635) Versions earlier than 9.0.0.159(C185E2R1P12T8) Versions earlier than 9.0.0.159(C461E2R1P11T8) Versions earlier than 9.0.0.160(C432E7R1P11T8) Versions earlier than 9.0.0.161(C605E2R1P12T8) Versions earlier than 9.0.0.168(C636E7R1P13T8)

EulerOS versions 2.2.RC3 2.2.RC5 V200R002C20 V200R003C00 V200R005C00

Figo-AL00A versions Versions earlier than 8.0.0.178(C00) Versions earlier than 8.0.0.178(C00)

Figo-L03 versions Versions earlier than 8.0.0.145(C605)

Figo-L11 versions Versions earlier than 8.0.0.137(C782) Versions earlier than 8.0.0.138(C782) Versions earlier than 8.0.0.155(C432) Versions earlier than 8.0.0.159(C432)

Figo-L21 versions Versions earlier than 8.0.0.138(C185) Versions earlier than 8.0.0.139(C635)

Figo-L23 versions Versions earlier than 8.0.0.144(C605)

Figo-L31 versions Versions earlier than 8.0.0.162(C432)

Florida-AL10B versions Versions earlier than 8.0.0.172(C00)

Florida-L21 versions Versions earlier than 8.0.0.127(C432) Versions earlier than 8.0.0.128(C185) Versions earlier than 8.0.0.129(C605)

Florida-L23 versions Versions earlier than 8.0.0.136(C605)

HUAWEI B618,HUAWEI 4G Router B618 versions Versions earlier than B618s-22dTCPU-V800R001B198D11SP00C00 Versions earlier than B618s-22dTCPU-V800R001B198D11SP00C00

HUAWEI Mobile WiFi Pro2,HUAWEI Mobile WiFi 2 Pro,Huawei Mobile WiFi 2 Pro versions Versions earlier than E5885Ls-93aTCPU-V200R001B191D63SP00C00

HUAWEI P smart versions Versions earlier than 8.0.0.131(ZAFC185)

HUAWEI P smart,HUAWEI Y7s versions Versions earlier than 8.0.0.111(C636) Versions earlier than 8.0.0.112(C636)

HUAWEI P20 versions 6.0.1.3(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 9.0.0.125(C00E76R1P21T8)

HUAWEI P20 Pro versions 8.1.0.176(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00) Versions earlier than 8.1.0.167(C00)

HUAWEI P20 lite versions Versions earlier than 8.0.0.147(C605) Versions earlier than 8.0.0.148(C605) Versions earlier than 8.0.0.151(C432)

HUAWEI Y6 2018 versions Versions earlier than 8.0.0.140(C432CUSTC432D1) Versions earlier than 8.0.0.142(C432CUSTC432D1) Versions earlier than 8.0.0.143(C185CUSTC185D1) Versions earlier than 8.0.0.143(C185CUSTC185D1) Versions earlier than 8.0.0.143(C185CUSTC185D1) Versions earlier than 8.0.0.144(C636CUSTC636D1) Versions earlier than 8.0.0.144(C636CUSTC636D1) Versions earlier than 8.0.0.146(C185CUSTC185D1)

HUAWEI Y6 Prime 2018 versions Versions earlier than 8.0.0.142(C569CUSTC569D1) Versions earlier than 8.0.0.142(C569CUSTC569D1) Versions earlier than 8.0.0.143(C461CUSTC461D1) Versions earlier than 8.0.0.143(C461CUSTC461D1) Versions earlier than 8.0.0.144(C185CUSTC185D1) Versions earlier than 8.0.0.144(C185CUSTC185D1)

HUAWEI Y7 2018 versions Versions earlier than 8.0.0.139(C432CUSTC432D1) Versions earlier than 8.0.0.139(C432CUSTC432D1) Versions earlier than 8.0.0.142(C185CUSTC185D1) Versions earlier than 8.0.0.150(C569CUSTC569D1) Versions earlier than 8.0.0.153(C185CUSTC185D1) Versions earlier than 8.0.0.158(C605CUSTC605D1) Versions earlier than 8.0.0.160(C782CUSTC782D1)

HUAWEI Y7 Prime 2018 versions Versions earlier than 8.0.0.135(C432CUSTC432D1) Versions earlier than 8.0.0.147(C185CUSTC185D1)

HUAWEI Y7 Pro 2018 versions Versions earlier than 8.0.0.146(C636CUSTC636D1)

HUAWEI nova 3e versions Versions earlier than 8.0.0.156(C636)

HUAWEI nova 3e,HUAWEI P20 lite versions Versions earlier than 8.0.0.145(ZAFC185) Versions earlier than 8.0.0.146(C605)

Leland-AL00A versions Versions earlier than 8.0.0.182(C00) Versions earlier than 8.0.0.182(C00)

Leland-AL10B versions Versions earlier than 8.0.0.133(C00)

Leland-L21A versions Versions earlier than 8.0.0.133(C185) Versions earlier than 8.0.0.133(C636)

Leland-L31A versions Versions earlier than 8.0.0.138(C432) Versions earlier than 8.0.0.138(C432)

London-AL30A versions Versions earlier than 8.0.0.215(C00)

London-AL40B versions Versions earlier than 8.0.0.216(C00)

London-L22 versions Versions earlier than 8.0.0.147(C636CUSTC636D1)

London-L29 versions Versions earlier than 8.0.0.135(C461CUSTC461D1) Versions earlier than 8.0.0.137(C432CUSTC432D1) Versions earlier than 8.0.0.144(C185CUSTC185D1) Versions earlier than 8.0.0.145(C636CUSTC636D1)

Mobile WiFi2(Cat6) versions Versions earlier than E5785Lh-22cTCPU-V200R001B191D63SP00C00

Schubert-AL09A versions Versions earlier than 8.0.0.173(C635) Versions earlier than 8.0.0.186(C432) Versions earlier than 8.0.0.187(C185)

Schubert-W09A versions Versions earlier than 8.0.0.173(C567) Versions earlier than 8.0.0.173(C635) Versions earlier than 8.0.0.185(C432)

Selina-L02 versions Versions earlier than C432B159

Toronto-L01 versions Versions earlier than C464B164CUSTC464D001

Toronto-L03 versions Versions earlier than C469B191CUSTC469D001

Toronto-L21 versions Versions earlier than C10B178CUSTC10D001 Versions earlier than C432B180CUSTC432D001 Versions earlier than C432B181CUSTC432D001 Versions earlier than C569B178CUSTC569D001 Versions earlier than C569B182CUSTC569D001

Toronto-L22 versions Versions earlier than C636B189CUSTC636D001

Toronto-L23 versions Versions earlier than C469B190CUSTC469D001

Huawei 4G routing 2 versions Versions earlier than 8.0.1.9(H183SP3C00)

Huawei Enjoy 8 versions Versions earlier than 8.0.0.215(C00) Versions earlier than 8.0.0.215(C00)

Honor Play 7A versions Versions earlier than 8.0.0.195(C00) Versions earlier than 8.0.0.195(C00)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://www.huawei.com/en/psirt/security-advisories/huawei-sa-20190123-01-linux-en");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

# nb: Unknown device (no VRP), no public vendor advisory or general inconsistent / broken data
